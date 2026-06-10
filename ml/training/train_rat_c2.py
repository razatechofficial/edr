#!/usr/bin/env python3
"""Supervised LightGBM classifier for RAT C2 beacon detection.

Generates synthetic RAT C2 beacon patterns (regular connection intervals,
DGA-like domains, low-volume keepalive traffic, unusual TLS fingerprints)
and benign background traffic, then trains a LightGBM model to distinguish
C2 beaconing from normal network activity.

Usage:
    python train_rat_c2.py --output-dir ./output
"""

from __future__ import annotations

import argparse
import csv
import logging
import math
import random
from pathlib import Path

import lightgbm as lgb
import numpy as np
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

from utils.evaluation import evaluate_binary_classifier
from utils.features import RatC2FeatureEncoder, RATC2_FEATURE_COUNT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("train_rat_c2")

SEED = 42
rng = random.Random(SEED)
np_rng = np.random.RandomState(SEED)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train RAT C2 beacon detector")
    p.add_argument("--output-dir", type=str, default="./output")
    p.add_argument("--n-normal", type=int, default=50000,
                   help="Number of benign samples")
    p.add_argument("--n-c2", type=int, default=15000,
                   help="Number of C2 beacon samples")
    p.add_argument("--n-estimators", type=int, default=500)
    p.add_argument("--learning-rate", type=float, default=0.05)
    p.add_argument("--max-depth", type=int, default=10)
    p.add_argument("--num-leaves", type=int, default=64)
    p.add_argument("--seed", type=int, default=SEED)
    return p.parse_args()


# ---------------------------------------------------------------------------
# Synthetic data generation
# ---------------------------------------------------------------------------

_COMMON_PORTS = [80, 443, 53, 22, 8080, 8443, 3306, 5432, 6379, 25, 465, 993]
_DGA_TLDS = [".com", ".net", ".org", ".xyz", ".top", ".site", ".info",
             ".club", ".online", ".work"]
_DGA_CONSONANTS = "bcdfghjklmnpqrstvwxz"
_DGA_VOWELS = "aeiou"
_DGA_DIGITS = "0123456789"

_KNOWN_C2_PORTS = [443, 8080, 8443, 8888, 4443, 1337, 4444, 5555,
                   6666, 7777, 8443, 9001, 9002, 11000, 16000, 18000]


def _random_dga_label(length: int = None) -> str:
    if length is None:
        length = rng.randint(8, 28)
    label = []
    for i in range(length):
        if rng.random() < 0.6:
            label.append(rng.choice(_DGA_CONSONANTS))
        elif rng.random() < 0.8:
            label.append(rng.choice(_DGA_DIGITS))
        else:
            label.append(rng.choice(_DGA_VOWELS))
    return "".join(label)


def _random_dga_domain() -> str:
    label = _random_dga_label()
    tld = rng.choice(_DGA_TLDS)
    return label + tld


def _janus_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    ln = len(s)
    for n in freq.values():
        p = n / ln
        ent -= p * math.log2(p)
    return ent


def _random_ja3() -> str:
    """Generate a random JA3 fingerprint."""
    versions = ["769", "770", "771", "772"]
    ciphers = ",".join(str(rng.randint(0, 65535)) for _ in range(rng.randint(3, 12)))
    extensions = ",".join(str(rng.randint(0, 65535)) for _ in range(rng.randint(2, 8)))
    curves = ",".join(str(rng.randint(0, 65535)) for _ in range(rng.randint(1, 5)))
    ec_points = ",".join(str(rng.randint(0, 255)) for _ in range(rng.randint(1, 3)))
    return f"{rng.choice(versions)},{ciphers},{extensions},{curves},{ec_points}"


def generate_c2_beacon_samples(n: int) -> list[dict]:
    """Generate RAT C2 beacon traffic samples."""
    samples = []
    for _ in range(n):
        is_dga = rng.random() < 0.4  # 40% DGA domain
        dest_port = rng.choice(_KNOWN_C2_PORTS)

        # Beacon timing features
        interval = rng.gauss(5.0, 1.5)  # mean 5s interval, low variance
        if interval < 0.1:
            interval = 0.1

        # Small data transfers typical of C2 keepalive
        bytes_in = rng.randint(64, 4096)
        bytes_out = rng.randint(64, 8192)

        # Duration
        duration_ms = rng.randint(100, 30000)

        # JA3 fingerprint (C2 tools often use unusual cipher suites)
        ja3 = _random_ja3() if rng.random() < 0.7 else ""

        # SNI (C2 often uses DGA domains or no SNI)
        if is_dga:
            domain = _random_dga_domain()
            sni = domain
        else:
            domain = ""
            sni = ""

        samples.append({
            "src_port": rng.randint(49152, 65535),
            "dest_port": dest_port,
            "protocol": "tcp" if rng.random() < 0.95 else "udp",
            "timestamp": rng.uniform(0, 1),
            "domain": domain,
            "dest_ip": f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "duration_ms": duration_ms,
            "ja3": ja3,
            "sni": sni,
        })
    return samples


def generate_normal_samples(n: int) -> list[dict]:
    """Generate benign background traffic samples."""
    samples = []
    for _ in range(n):
        dest_port = rng.choice(_COMMON_PORTS)

        # Normal traffic has variable timing and larger data transfers
        bytes_in = rng.randint(256, 2 ** 20)  # up to 1 MB
        bytes_out = rng.randint(128, 2 ** 19)
        duration_ms = rng.randint(50, 300000)

        # Normal traffic usually uses standard JA3
        ja3 = _random_ja3() if rng.random() < 0.05 else ""

        # Normal traffic uses real domains or IPs
        if rng.random() < 0.3:
            domain = f"{rng.choice(['www', 'mail', 'api', 'cdn', 'static', 'blog'])}.{rng.choice(['google', 'microsoft', 'cloudflare', 'amazon', 'github', 'gitlab'])}.{rng.choice(['com', 'net', 'org', 'io'])}"
        else:
            domain = ""

        # Normal SNI
        sni = domain if domain and rng.random() < 0.8 else ""

        samples.append({
            "src_port": rng.randint(1024, 65535),
            "dest_port": dest_port,
            "protocol": "tcp" if rng.random() < 0.9 else "udp",
            "timestamp": rng.uniform(0, 1),
            "domain": domain or "",
            "dest_ip": f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "duration_ms": duration_ms,
            "ja3": ja3,
            "sni": sni,
        })
    return samples


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


def train(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Generating %d C2 beacon samples …", args.n_c2)
    c2 = generate_c2_beacon_samples(args.n_c2)

    logger.info("Generating %d normal samples …", args.n_normal)
    normal = generate_normal_samples(args.n_normal)

    encoder = RatC2FeatureEncoder()
    X_c2 = np.array([encoder.encode(s) for s in c2], dtype=np.float32)
    X_norm = np.array([encoder.encode(s) for s in normal], dtype=np.float32)

    X = np.concatenate([X_c2, X_norm], axis=0)
    y = np.concatenate([
        np.ones(len(c2), dtype=np.int32),
        np.zeros(len(normal), dtype=np.int32),
    ], axis=0)

    # Shuffle
    idx = np_rng.permutation(len(y))
    X = X[idx]
    y = y[idx]

    logger.info("Dataset: %d total, %.1f%% C2",
                len(y), 100 * y.mean())

    split = int(0.8 * len(y))
    X_train, X_val = X[:split], X[split:]
    y_train, y_val = y[:split], y[split:]

    # Compute class weights (C2 is minority)
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
        reg_alpha=0.1,
        reg_lambda=0.1,
        min_child_samples=20,
        random_state=args.seed,
        verbose=-1,
        n_jobs=-1,
    )
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)],
              eval_metric="auc", callbacks=[lgb.log_evaluation(50)])

    # Evaluate
    y_prob = model.predict_proba(X_val)[:, 1]
    y_pred = model.predict(X_val)
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
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

    # Feature importance
    imp = model.feature_importances_
    names = encoder.feature_names()
    top_n = sorted(zip(names, imp), key=lambda x: -x[1])[:10]
    logger.info("Top 10 features:")
    for name, val in top_n:
        logger.info("  %s: %.0f", name, val)

    # Save model
    model_path = output_dir / "rat_c2_detector.txt"
    model.booster_.save_model(str(model_path))
    logger.info("Saved model → %s", model_path)

    # --- Export to ONNX ---
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


if __name__ == "__main__":
    args = parse_args()
    train(args)
