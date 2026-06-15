#!/usr/bin/env python3
"""Create a proper ONNX for network_anomaly.
Since the 15-dim features are mostly categorical/binary, no reconstruction-based
method works well. We use a simple distance-based approach: measure Manhattan
distance from the benign centroid and normalize to 0..1.

This gives AUC ~0.75 for CIC-IDS2017 — not great, but it's a secondary detector.
The primary network detector is network_lgbm (AUC=0.939).
"""
from __future__ import annotations
import logging, sys
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
logger = logging.getLogger("fix_network_anomaly")

from utils.features import NETWORK_FEATURE_COUNT
from adapters.network_adapter import load as load_network

def main():
    output_dir = Path(__file__).resolve().parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    cfg = {
        "data_path": str(Path(__file__).resolve().parent.parent / "datasets" / "cic-ids2017" / "csv"),
        "max_samples": 100000,
        "dataset": "auto",
    }
    X, y, _ = load_network(cfg)
    # We need real attack samples; use what we have
    attack_mask = y == 1
    benign = X[~attack_mask]
    logger.info("Benign: %d, Attack: %d (%.2f%%)", len(benign), attack_mask.sum(), attack_mask.mean() * 100)

    # Centroid and per-feature MAD of benign traffic
    centroid = np.median(benign, axis=0)
    mad = np.median(np.abs(benign - centroid), axis=0)
    mad = np.clip(mad, 0.01, None)  # avoid div by zero

    # Score = normalized Manhattan distance from centroid
    dists = np.sum(np.abs(X - centroid) / mad, axis=1)
    max_dist = np.percentile(dists, 99.9)
    scores = np.clip(dists / max_dist, 0, 1)

    from sklearn.metrics import roc_auc_score, f1_score
    auc = roc_auc_score(y, scores)
    logger.info("Centroid distance model AUC=%.4f", auc)

    # Export: MatMul with inverse-MAD, ReduceSum, Clip → score
    import onnx
    from onnx import helper, TensorProto, numpy_helper

    mad_inv = (1.0 / mad).astype(np.float32)
    centroid_f32 = centroid.astype(np.float32)

    # Graph: input → Sub(centroid) → Abs → Mul(mad_inv) → ReduceSum(axis=1, keepdims=1) → Clip(0,1) → score
    sub = helper.make_node("Sub", ["input", "centroid"], ["centered"], "sub_centroid")
    abs_n = helper.make_node("Abs", ["centered"], ["abs_dev"], "abs_dev")
    mul = helper.make_node("Mul", ["abs_dev", "mad_inv"], ["norm_dev"], "norm_dev")
    rs = helper.make_node("ReduceSum", ["norm_dev"], ["raw_score"], "sum_dev", axes=[1], keepdims=1)
    clip = helper.make_node("Clip", ["raw_score"], ["score"], "clip_score", min=0.0, max=1.0)

    graph_def = helper.make_graph(
        nodes=[sub, abs_n, mul, rs, clip],
        name="network_anomaly",
        inputs=[helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, NETWORK_FEATURE_COUNT])],
        outputs=[helper.make_tensor_value_info("score", TensorProto.FLOAT, [None, 1])],
        initializer=[
            numpy_helper.from_array(centroid_f32, name="centroid"),
            numpy_helper.from_array(mad_inv, name="mad_inv"),
        ],
    )
    model = helper.make_model(graph_def, producer_name="edr_network_anomaly_v3")
    onnx.checker.check_model(model)

    onnx_path = output_dir / "network_anomaly.onnx"
    onnx.save(model, str(onnx_path))
    logger.info("ONNX saved: %d bytes", onnx_path.stat().st_size)

    import onnxruntime as ort
    sess = ort.InferenceSession(str(onnx_path))
    dummy = np.zeros((5, NETWORK_FEATURE_COUNT), dtype=np.float32)
    out = sess.run(None, {"input": dummy})[0]
    logger.info("Sample output: %s", out.flatten().tolist())
    logger.info("AUC on CIC-IDS2017: %.4f", auc)

if __name__ == "__main__":
    main()
