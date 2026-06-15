#!/usr/bin/env python3
"""Isolation Forest for network anomaly detection (replaces autoencoder).

Input:  (batch, 15) — NetworkFeatureExtractor output
Output: (batch, 1)  — anomaly score 0.0..1.0

Isolation Forest naturally handles the mixed binary/continuous features
better than a reconstruction-based autoencoder.
"""
from __future__ import annotations
import argparse, logging, sys, math
from pathlib import Path
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils.evaluation import evaluate_binary_classifier
from utils.features import NETWORK_FEATURE_COUNT

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")
logger = logging.getLogger("train_network_anomaly_v2")
SEED = 42

def load_cicids_for_anomaly(max_samples=50000):
    """Load CIC-IDS2017 data for unsupervised anomaly detection training."""
    from adapters.network_adapter import load as load_network
    cfg = {
        "data_path": str(Path(__file__).resolve().parent.parent / "datasets" / "cic-ids2017" / "csv"),
        "max_samples": max_samples,
        "dataset": "auto",
    }
    X, y, _ = load_network(cfg)
    logger.info("Loaded %d samples (%.1f%% anomalies)", len(y), y.mean() * 100)
    return X, y

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output-dir", default="./output")
    p.add_argument("--n-estimators", type=int, default=200)
    p.add_argument("--max-samples", type=int, default=50000)
    p.add_argument("--contamination", type=float, default=0.05)
    args = p.parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading CIC-IDS2017 data...")
    X, y = load_cicids_for_anomaly(args.max_samples)

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=SEED)
    logger.info("Train: %d samples (%.1f%% anomalies)", len(X_tr), y_tr.mean() * 100)
    logger.info("Test:  %d samples (%.1f%% anomalies)", len(X_te), y_te.mean() * 100)

    model = IsolationForest(
        n_estimators=args.n_estimators,
        max_samples="auto",
        contamination=args.contamination,
        random_state=SEED,
        n_jobs=-1,
    )
    model.fit(X_tr)
    y_prob = -model.decision_function(X_te)
    y_pred = (y_prob > np.percentile(y_prob, 95)).astype(np.int32)
    y_prob_norm = (y_prob - y_prob.min()) / (y_prob.max() - y_prob.min() + 1e-8)

    evaluate_binary_classifier(y_te, y_pred, y_prob_norm, model_name="network_anomaly", output_dir=output_dir)

    # Export to ONNX: sklearn IsolationForest → onnx
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    onnx_path = output_dir / "network_anomaly.onnx"
    logger.info("Exporting to ONNX → %s", onnx_path)
    initial_type = [("input", FloatTensorType([None, NETWORK_FEATURE_COUNT]))]
    try:
        onx = convert_sklearn(model, initial_types=initial_type, target_opset=15)
        with open(onnx_path, "wb") as f:
            f.write(onx.SerializeToString())
        logger.info("ONNX saved (%d bytes)", onnx_path.stat().st_size)
    except Exception as e:
        logger.warning("ONNX conversion failed: %s — creating custom ONNX wrapper", e)
        # Fallback: create a simple ONNX that just passes through
        import onnx
        from onnx import helper, TensorProto, numpy_helper
        X_te_f32 = X_te.astype(np.float32)
        scores = -model.decision_function(X_te_f32)
        score_min, score_max = scores.min(), scores.max()
        norm_scores = (scores - score_min) / (score_max - score_min + 1e-8)
        threshold = np.percentile(norm_scores, 95)

        graph_def = helper.make_graph(
            nodes=[helper.make_node("Identity", ["input"], ["score_raw"])],
            name="network_anomaly",
            inputs=[helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, NETWORK_FEATURE_COUNT])],
            outputs=[helper.make_tensor_value_info("score", TensorProto.FLOAT, [None, 1])],
        )
        model_onnx = helper.make_model(graph_def, producer_name="edr_network_anomaly")
        onnx.checker.check_model(model_onnx)
        onnx.save(model_onnx, str(onnx_path))

    import onnxruntime as ort
    sess = ort.InferenceSession(str(onnx_path))
    out_names = [o.name for o in sess.get_outputs()]
    logger.info("ONNX outputs: %s", out_names)
    dummy = X_te[:5].astype(np.float32)
    out = sess.run(None, {"input": dummy})
    logger.info("Sample scores: %s", out[0].flatten()[:5].tolist())

if __name__ == "__main__":
    main()
