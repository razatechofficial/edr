#!/usr/bin/env python3
"""Train XGBoost RAT C2 detector on CTU-13, export to ONNX.

Aims to break through the recall@lowFPR ceiling that LightGBM hits.
"""
from __future__ import annotations
import argparse, json, logging, sys
from pathlib import Path
import numpy as np
import xgboost as xgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils.features import RatC2FeatureEncoder, NETWORK_FEATURE_COUNT
from utils.evaluation import evaluate_binary_classifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
logger = logging.getLogger("train_rat_c2_xgb")
SEED = 42
np.random.seed(SEED)

DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets" / "rat"
INTERNAL_PREFIXES = ("147.32.84.", "147.32.85.", "147.32.86.", "147.32.87.",
                     "147.32.88.", "147.32.89.")

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--output-dir", type=str, default="./output")
    p.add_argument("--n-estimators", type=int, default=500)
    p.add_argument("--max-depth", type=int, default=6)
    p.add_argument("--learning-rate", type=float, default=0.05)
    p.add_argument("--reg-alpha", type=float, default=2.0)
    p.add_argument("--reg-lambda", type=float, default=2.0)
    p.add_argument("--min-child-weight", type=float, default=10)
    p.add_argument("--seed", type=int, default=SEED)
    return p.parse_args()

def parse_timestamp(ts_str: str) -> float:
    try:
        dt = __import__("datetime").datetime.strptime(ts_str.strip(), "%Y/%m/%d %H:%M:%S.%f")
        return (dt.hour * 3600 + dt.minute * 60 + dt.second) / 86400.0
    except ValueError:
        return 0.0

def is_botnet(label: str | None) -> bool:
    if not label:
        return False
    ll = label.strip().lower()
    return ll.startswith("flow=from-botnet") or ll.startswith("flow=botnet") or ll.startswith("flow=cc")

def load_binetflow(filepath: Path, max_botnet=50000, max_bg=100000, bg_skip=0.0):
    botnet, bg = [], []
    rng = np.random.RandomState(SEED)
    if not filepath.exists():
        return botnet, bg
    with open(filepath) as f:
        for row in __import__("csv").DictReader(f):
            label = row.get("Label", "")
            is_bot = is_botnet(label)
            if is_bot:
                if len(botnet) >= max_botnet:
                    continue
            else:
                if len(bg) >= max_bg:
                    continue
                if bg_skip > 0 and rng.random() < bg_skip:
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
            except (ValueError, KeyError):
                continue
            is_src_int = src_addr.startswith(INTERNAL_PREFIXES)
            is_dst_int = dst_addr.startswith(INTERNAL_PREFIXES)
            if is_src_int:
                bo, bi = src_bytes, tot_bytes - src_bytes
            elif is_dst_int:
                bi, bo = src_bytes, tot_bytes - src_bytes
            else:
                bi, bo = src_bytes, tot_bytes - src_bytes
            conn = {
                "src_port": sport, "dest_port": dport, "protocol": proto,
                "timestamp": parse_timestamp(start_time), "domain": "",
                "dest_ip": dst_addr, "bytes_in": max(0, bi), "bytes_out": max(0, bo),
                "duration_ms": int(dur * 1000), "ja3": "", "sni": "",
            }
            (botnet if is_bot else bg).append(conn)
    logger.info("  %s: botnet=%d bg=%d", filepath.name, len(botnet), len(bg))
    return botnet, bg

def train(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    encoder = RatC2FeatureEncoder()

    scenarios = [
        ("ctu13_scenario_01_Neris", "bidirectional_capture20110810.binetflow"),
        ("ctu13_scenario_02_Neris", "bidirectional_capture20110811.binetflow"),
        ("ctu13_scenario_03_Rbot",  "bidirectional_capture20110812.binetflow"),
        ("ctu13_scenario_07_Sogou", "bidirectional_capture20110816-2.binetflow"),
        ("ctu13_scenario_08_Murlo", "bidirectional_capture20110816-3.binetflow"),
        ("ctu13_scenario_09_Neris", "bidirectional_capture20110817.binetflow"),
    ]

    all_botnet, all_bg = [], []
    for sdir, fname in scenarios:
        fpath = DATASET_DIR / sdir / fname
        if not fpath.exists():
            continue
        logger.info("Loading %s/%s …", sdir, fname)
        bot, bg = load_binetflow(fpath, max_botnet=50000, max_bg=100000, bg_skip=0.85)
        all_botnet.extend(bot)
        all_bg.extend(bg)

    logger.info("Total: botnet=%d background=%d", len(all_botnet), len(all_bg))
    X_c2 = np.array([encoder.encode(s) for s in all_botnet], dtype=np.float32)
    X_bg = np.array([encoder.encode(s) for s in all_bg], dtype=np.float32)
    X = np.concatenate([X_c2, X_bg])
    y = np.concatenate([np.ones(len(all_botnet)), np.zeros(len(all_bg))]).astype(np.int32)

    idx = np.random.RandomState(SEED).permutation(len(y))
    X, y = X[idx], y[idx]

    split = int(0.8 * len(y))
    X_tr, X_val = X[:split], X[split:]
    y_tr, y_val = y[:split], y[split:]

    n_c2 = int(y_tr.sum())
    n_norm = len(y_tr) - n_c2
    scale_pos_weight = n_norm / max(n_c2, 1)
    logger.info("Train: %d C2, %d bg (scale_pos_weight=%.2f)", n_c2, n_norm, scale_pos_weight)

    logger.info("Training XGBoost (n_est=%d, depth=%d, lr=%.3f, reg_a=%.2f, reg_l=%.2f) …",
                args.n_estimators, args.max_depth, args.learning_rate,
                args.reg_alpha, args.reg_lambda)

    model = xgb.XGBClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=args.reg_alpha,
        reg_lambda=args.reg_lambda,
        min_child_weight=args.min_child_weight,
        scale_pos_weight=scale_pos_weight,
        max_delta_step=5,
        random_state=args.seed,
        n_jobs=-1,
        verbosity=0,
    )
    model.fit(X_tr, y_tr, eval_set=[(X_val, y_val)], verbose=False)

    y_pred = model.predict(X_val)
    y_prob = model.predict_proba(X_val)[:, 1]
    evaluate_binary_classifier(y_val, y_pred, y_prob, model_name="rat_c2_detector", output_dir=output_dir)

    # Export to ONNX
    onnx_path = output_dir / "rat_c2_detector.onnx"
    logger.info("Exporting to ONNX → %s", onnx_path)
    initial_type = [("input", FloatTensorType([None, 22]))]
    onnx_model = onnxmltools.convert_xgboost(
        model, initial_types=initial_type, target_opset=15,
    )
    onnxmltools.utils.save_model(onnx_model, str(onnx_path))
    logger.info("ONNX saved (%d bytes)", onnx_path.stat().st_size)

    # Post-process: keep only probabilities[1] as "score" output
    import onnx
    from onnx import helper, TensorProto
    m = onnx.load(str(onnx_path))

    # Find the probabilities output name
    prob_name = None
    for node in m.graph.node:
        for o in node.output:
            if o == "probabilities":
                prob_name = o
                break
        if prob_name:
            break

    if prob_name:
        # Rename to keep original as a temp
        tmp_name = prob_name + "_raw"
        for node in m.graph.node:
            for i, o in enumerate(node.output):
                if o == prob_name:
                    node.output[i] = tmp_name

        # Gather node to extract class 1: probabilities[:, 1]
        idx_init = helper.make_tensor("gather_idx", TensorProto.INT64, [1], [1])
        m.graph.initializer.append(idx_init)
        gather = helper.make_node("Gather", [tmp_name, "gather_idx"], ["score"],
                                  name="extract_class1", axis=1)
        m.graph.node.append(gather)

        # Replace outputs: remove label, keep only score
        score_out = helper.make_tensor_value_info("score", TensorProto.FLOAT, [None, 1])
        del m.graph.output[:]
        m.graph.output.extend([score_out])

    onnx.save(m, str(onnx_path))
    logger.info("ONNX post-processed: output -> score")

    # Validate
    import onnxruntime as ort
    sess = ort.InferenceSession(str(onnx_path))
    for o in sess.get_outputs():
        logger.info("  Output '%s': shape=%s", o.name, o.shape)
    dummy = X_val[:5].astype(np.float32)
    out = sess.run(None, {"input": dummy})
    scores = np.array(out[0]).flatten()
    logger.info("  Score sample: %s", scores[:5].tolist())
    assert scores.min() >= 0.0 and scores.max() <= 1.0, "Scores out of [0,1] range"
    logger.info("ONNX validation passed ✓")

if __name__ == "__main__":
    train(parse_args())
