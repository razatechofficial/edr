#!/usr/bin/env python3
"""Supervised LightGBM classifier for RAT C2 beacon detection using real CTU-13 data.

Loads labeled bidirectional binetflow files from CTU-13 scenarios 1–3, 7–9,
maps flow fields to the 22-dim RatC2FeatureEncoder, and trains LightGBM
with proper handling for extreme class imbalance.

Usage:
    python train_rat_c2_ctu13.py --output-dir ./output
"""

from __future__ import annotations

import argparse
import csv
import logging
import math
import random
from datetime import datetime
from pathlib import Path

import lightgbm as lgb
import numpy as np
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

from utils.features import RatC2FeatureEncoder, RATC2_FEATURE_COUNT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("train_rat_c2_ctu13")

SEED = 42
rng = random.Random(SEED)
np_rng = np.random.RandomState(SEED)

# CTU-13 dataset paths relative to this repo
DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets" / "rat"

# Internal network prefix used in CTU-13 (CVUT campus network)
INTERNAL_PREFIXES = ("147.32.84.", "147.32.85.", "147.32.86.", "147.32.87.",
                     "147.32.88.", "147.32.89.")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train RAT C2 beacon detector on CTU-13")
    p.add_argument("--output-dir", type=str, default="./output")
    p.add_argument("--n-background", type=int, default=600000,
                   help="Max background samples to use (subsampled)")
    p.add_argument("--n-estimators", type=int, default=200)
    p.add_argument("--learning-rate", type=float, default=0.1)
    p.add_argument("--max-depth", type=int, default=8)
    p.add_argument("--num-leaves", type=int, default=31)
    p.add_argument("--seed", type=int, default=SEED)
    return p.parse_args()


def parse_timestamp(ts_str: str) -> float:
    """Parse CTU-13 timestamp format to time-of-day fraction [0,1)."""
    try:
        dt = datetime.strptime(ts_str.strip(), "%Y/%m/%d %H:%M:%S.%f")
        seconds = dt.hour * 3600 + dt.minute * 60 + dt.second
        return seconds / 86400.0
    except ValueError:
        return 0.0


def is_botnet_flow(label: str | None) -> bool:
    """True if the flow label indicates botnet/C2/malicious traffic."""
    if not label:
        return False
    label_lower = label.strip().lower()
    if label_lower.startswith("flow=from-botnet"):
        return True
    if label_lower.startswith("flow=botnet"):
        return True
    if label_lower.startswith("flow=cc"):
        return True
    if label_lower.startswith("flow=c&c"):
        return True
    if label_lower.startswith("flow=legitimate"):
        return False
    if label_lower.startswith("flow=background"):
        return False
    if label_lower.startswith("flow=from-normal"):
        return False
    if label_lower.startswith("flow=to-background"):
        return False
    return False


def load_binetflow(filepath: Path, max_botnet: int = 0, max_bg: int = 0,
                   bg_skip: float = 0.0) -> tuple[list[dict], list[dict]]:
    """Load flows from a bidirectional binetflow file.

    Returns (botnet_samples, background_samples).
    """
    botnet: list[dict] = []
    bg: list[dict] = []

    if not filepath.exists():
        logger.warning("  File not found: %s", filepath)
        return botnet, bg

    line_count = 0
    skip_counter = 0
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            line_count += 1
            label = row.get("Label", "")
            is_bot = is_botnet_flow(label)

            if is_bot:
                if max_botnet and len(botnet) >= max_botnet:
                    continue
            else:
                if max_bg and len(bg) >= max_bg:
                    continue
                # Random subsample background to reduce skew
                if bg_skip > 0 and rng.random() < bg_skip:
                    skip_counter += 1
                    continue

            try:
                dur = float(row.get("Dur", 0))
                proto = row.get("Proto", "").lower().strip()
                sport = int(row.get("Sport", 0))
                dport = int(row.get("Dport", 0))
                src_addr = row.get("SrcAddr", "")
                dst_addr = row.get("DstAddr", "")
                tot_bytes = int(row.get("TotBytes", 0))
                src_bytes = int(row.get("SrcBytes", 0))
                start_time = row.get("StartTime", "")
            except (ValueError, KeyError) as e:
                logger.debug("  Skipping malformed row %d: %s", line_count, e)
                continue

            # Determine bytes_in/bytes_out from infected host perspective.
            # Infected hosts in CTU-13 are on the internal CVUT network.
            # If the source is internal, then SrcBytes is outgoing (bytes_out).
            # If the dest is internal, SrcBytes is incoming (bytes_in).
            is_src_internal = src_addr.startswith(INTERNAL_PREFIXES)
            is_dst_internal = dst_addr.startswith(INTERNAL_PREFIXES)

            if is_src_internal:
                bytes_out = src_bytes
                bytes_in = tot_bytes - src_bytes
            elif is_dst_internal:
                bytes_in = src_bytes
                bytes_out = tot_bytes - src_bytes
            else:
                bytes_in = src_bytes
                bytes_out = tot_bytes - src_bytes

            # Constrain to non-negative
            bytes_in = max(0, bytes_in)
            bytes_out = max(0, bytes_out)

            conn = {
                "src_port": sport,
                "dest_port": dport,
                "protocol": proto,
                "timestamp": parse_timestamp(start_time),
                "domain": "",
                "dest_ip": dst_addr,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "duration_ms": int(dur * 1000),
                "ja3": "",
                "sni": "",
            }

            if is_bot:
                botnet.append(conn)
            else:
                bg.append(conn)

            if line_count % 500000 == 0:
                logger.info("  Read %d lines (botnet=%d, bg=%d)",
                            line_count, len(botnet), len(bg))

    logger.info("  File %s: %d lines, botnet=%d, bg=%d (skip=%d)",
                filepath.name, line_count, len(botnet), len(bg), skip_counter)
    return botnet, bg


def train(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    encoder = RatC2FeatureEncoder()

    # -----------------------------------------------------------------------
    # Load CTU-13 data
    # -----------------------------------------------------------------------
    scenarios = [
        ("ctu13_scenario_01_Neris", "bidirectional_capture20110810.binetflow"),
        ("ctu13_scenario_02_Neris", "bidirectional_capture20110811.binetflow"),
        ("ctu13_scenario_03_Rbot",  "bidirectional_capture20110812.binetflow"),
        ("ctu13_scenario_07_Sogou", "bidirectional_capture20110816-2.binetflow"),
        ("ctu13_scenario_08_Murlo", "bidirectional_capture20110816-3.binetflow"),
        ("ctu13_scenario_09_Neris", "bidirectional_capture20110817.binetflow"),
    ]

    all_botnet: list[dict] = []
    all_bg: list[dict] = []

    # Target: balanced training with ~3:1 background:botnet ratio
    total_botnet_estimate = 215000
    bg_per_scenario = max(100000, args.n_background // len(scenarios))
    bg_skip_ratio = 0.0  # adjusted per scenario below

    for scenario_dir, filename in scenarios:
        filepath = DATASET_DIR / scenario_dir / filename
        if not filepath.exists():
            continue
        logger.info("Loading %s/%s …", scenario_dir, filename)

        # Dynamically compute skip ratio for background subsampling
        # Rough estimate based on known botnet counts
        est_botnet = {
            "ctu13_scenario_01_Neris": 2500,
            "ctu13_scenario_02_Neris": 21000,
            "ctu13_scenario_03_Rbot": 5100,
            "ctu13_scenario_07_Sogou": 100,
            "ctu13_scenario_08_Murlo": 700,
            "ctu13_scenario_09_Neris": 185000,
        }.get(scenario_dir, 1000)

        est_bg = {
            "ctu13_scenario_01_Neris": 993000,
            "ctu13_scenario_02_Neris": 1787000,
            "ctu13_scenario_03_Rbot": 2078000,
            "ctu13_scenario_07_Sogou": 114000,
            "ctu13_scenario_08_Murlo": 352000,
            "ctu13_scenario_09_Neris": 1902000,
        }.get(scenario_dir, 100000)

        # Skip ratio: keep only enough background to get ~3:1 ratio
        target_bg = min(est_botnet * 3, bg_per_scenario)
        if est_bg > target_bg and est_bg > 0:
            bg_skip = 1.0 - (target_bg / est_bg)
        else:
            bg_skip = 0.0

        bot, bg = load_binetflow(
            filepath,
            max_botnet=min(50000, total_botnet_estimate),
            max_bg=bg_per_scenario,
            bg_skip=bg_skip,
        )
        all_botnet.extend(bot)
        all_bg.extend(bg)

    logger.info("Total loaded: botnet=%d, background=%d",
                len(all_botnet), len(all_bg))

    if len(all_botnet) == 0:
        logger.error("No botnet samples found! Check data paths.")
        return

    # -----------------------------------------------------------------------
    # Build feature matrix
    # -----------------------------------------------------------------------
    logger.info("Encoding features …")
    X_c2 = np.array([encoder.encode(s) for s in all_botnet], dtype=np.float32)
    X_bg = np.array([encoder.encode(s) for s in all_bg], dtype=np.float32)

    X = np.concatenate([X_c2, X_bg], axis=0)
    y = np.concatenate([
        np.ones(len(all_botnet), dtype=np.int32),
        np.zeros(len(all_bg), dtype=np.int32),
    ], axis=0)

    # Shuffle
    idx = np_rng.permutation(len(y))
    X = X[idx]
    y = y[idx]

    logger.info("Dataset: %d total, %.1f%% C2 (botnet=%d, bg=%d)",
                len(y), 100 * y.mean(), int(y.sum()), len(y) - int(y.sum()))

    # Train/val split
    split = int(0.8 * len(y))
    X_train, X_val = X[:split], X[split:]
    y_train, y_val = y[:split], y[split:]

    # Class weights
    n_c2 = int(y_train.sum())
    n_norm = len(y_train) - n_c2
    scale_pos_weight = n_norm / max(n_c2, 1)

    logger.info("Training LightGBM (scale_pos_weight=%.2f) …", scale_pos_weight)
    model = lgb.LGBMClassifier(
        n_estimators=args.n_estimators,
        learning_rate=args.learning_rate,
        max_depth=args.max_depth,
        num_leaves=args.num_leaves,
        scale_pos_weight=scale_pos_weight,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.5,
        reg_lambda=0.5,
        min_child_samples=50,
        min_data_in_leaf=100,
        random_state=args.seed,
        verbose=-1,
        n_jobs=-1,
    )
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)],
              eval_metric="auc", callbacks=[lgb.log_evaluation(50)])

    # -----------------------------------------------------------------------
    # Evaluate
    # -----------------------------------------------------------------------
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                  f1_score, roc_auc_score, confusion_matrix)

    y_prob = model.predict_proba(X_val)[:, 1]
    y_pred = model.predict(X_val)

    results = {
        "accuracy": float(accuracy_score(y_val, y_pred)),
        "precision": float(precision_score(y_val, y_pred, zero_division=0)),
        "recall": float(recall_score(y_val, y_pred, zero_division=0)),
        "f1": float(f1_score(y_val, y_pred, zero_division=0)),
        "auc": float(roc_auc_score(y_val, y_prob)),
    }
    logger.info("Validation results:")
    for k, v in results.items():
        logger.info("  %s: %.4f", k, v)

    cm = confusion_matrix(y_val, y_pred)
    logger.info("Confusion matrix:\n%s", cm)

    # Feature importance
    imp = model.feature_importances_
    names = encoder.feature_names()
    top_n = sorted(zip(names, imp), key=lambda x: -x[1])[:10]
    logger.info("Top 10 features:")
    for name, val in top_n:
        logger.info("  %s: %.0f", name, val)

    # -----------------------------------------------------------------------
    # Save model
    # -----------------------------------------------------------------------
    model_path = output_dir / "rat_c2_detector.txt"
    model.booster_.save_model(str(model_path))
    logger.info("Saved model → %s", model_path)

    # -----------------------------------------------------------------------
    # Export to ONNX with single float32 score output
    # -----------------------------------------------------------------------
    initial_type = [("input", FloatTensorType([None, RATC2_FEATURE_COUNT]))]
    onnx_model = onnxmltools.convert_lightgbm(
        model.booster_, initial_types=initial_type, target_opset=15, zipmap=False,
    )
    onnx_path = output_dir / "rat_c2_detector.onnx"
    onnxmltools.utils.save_model(onnx_model, str(onnx_path))
    logger.info("Saved ONNX → %s", onnx_path)

    # Post-process: add Gather node to extract class-1 probability as single score
    import onnx
    from onnx import helper, TensorProto

    m = onnx.load(str(onnx_path))
    prob_node_name = None
    for node in m.graph.node:
        if 'probabilities' in node.output:
            prob_node_name = node.output[0]
            break

    if prob_node_name:
        original_prob_name = prob_node_name + "_raw"
        for node in m.graph.node:
            for i, o in enumerate(node.output):
                if o == prob_node_name:
                    node.output[i] = original_prob_name

        indices_init = helper.make_tensor(
            name="gather_indices",
            data_type=TensorProto.INT64,
            dims=[1],
            vals=[1],
        )
        m.graph.initializer.append(indices_init)

        gather_node = helper.make_node(
            "Gather",
            inputs=[original_prob_name, "gather_indices"],
            outputs=["score"],
            name="extract_class1_proba",
            axis=1,
        )
        m.graph.node.append(gather_node)

        score_output = helper.make_tensor_value_info(
            "score", TensorProto.FLOAT, [None, 1],
        )
        del m.graph.output[:]
        m.graph.output.extend([score_output])
    else:
        # If no probabilities output (single-output model), rename it to score
        for i, o in enumerate(m.graph.output):
            m.graph.output[i].name = "score"

    onnx.save(m, str(onnx_path))
    logger.info("ONNX graph modified: outputs -> score")

    # Validate
    import onnxruntime as ort
    sess = ort.InferenceSession(str(onnx_path))
    for o in sess.get_outputs():
        logger.info("  Output '%s': shape=%s", o.name, o.shape)
    dummy = np.random.randn(3, RATC2_FEATURE_COUNT).astype(np.float32)
    out = sess.run(None, {"input": dummy})
    scores = np.array(out[0]).flatten()
    logger.info("  Score sample: %s", scores.tolist())
    assert scores.min() >= 0.0 and scores.max() <= 1.0, "Scores out of [0,1] range"
    logger.info("ONNX validation passed ✓")

    # Model file size
    size_kb = onnx_path.stat().st_size / 1024
    logger.info("Model size: %.1f KB", size_kb)


if __name__ == "__main__":
    args = parse_args()
    train(args)
