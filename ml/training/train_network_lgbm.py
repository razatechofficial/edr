#!/usr/bin/env python3
"""Supervised LightGBM classifier for network attack detection.

Trains on labeled CIC-IDS2017 + UNSW-NB15 data. Exports to ONNX.

This replaces the unsupervised autoencoder approach with a supervised one
for production-grade detection in government/banking/intelligence environments.

Usage:
    python train_network_lgbm.py \\
        --data-path ml/datasets/cic-ids2017/csv,ml/datasets/edr_datasets/unsw-nb15 \\
        --output-dir ./output
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

from utils.datasets import split_dataset
from utils.evaluation import evaluate_binary_classifier
from utils.features import NETWORK_FEATURE_COUNT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("train_network_lgbm")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train LightGBM network attack classifier")
    p.add_argument(
        "--data-path",
        type=str,
        default=None,
        help="Comma-separated paths to CIC-IDS2017/2018 CSVs or directories, and UNSW-NB15",
    )
    p.add_argument("--ctu13-path", type=str, default=None,
                    help="Path to CTU-13 dataset directory")
    p.add_argument("--max-samples", type=int, default=2_000_000,
                    help="Cap total samples (0 = unlimited)")
    p.add_argument("--output-dir", type=str, default="./output")
    p.add_argument("--n-estimators", type=int, default=500)
    p.add_argument("--learning-rate", type=float, default=0.05)
    p.add_argument("--max-depth", type=int, default=12)
    p.add_argument("--num-leaves", type=int, default=64)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def load_data(args: argparse.Namespace) -> tuple[np.ndarray, np.ndarray]:
    from adapters.network_adapter import load as load_network
    from adapters.ctu13_adapter import load as load_ctu13

    all_X, all_y = [], []

    if args.data_path:
        paths = [p.strip() for p in args.data_path.split(",")]
        for data_path in paths:
            cfg = {
                "data_path": data_path,
                "max_samples": args.max_samples,
                "dataset": "auto",
            }
            X, y, meta = load_network(cfg)
            all_X.append(X)
            all_y.append(y)
            logger.info("  %s: %d samples (%d attack)", data_path, len(y), int(y.sum()))

    if args.ctu13_path:
        ctu_cfg = {
            "data_path": args.ctu13_path,
            "max_samples": args.max_samples,
        }
        Xc, yc, metac = load_ctu13(ctu_cfg)
        all_X.append(Xc)
        all_y.append(yc)
        logger.info("  CTU-13: %d samples (%d botnet)", len(yc), int(yc.sum()))

    if not all_X:
        logger.info("No data paths provided; generating synthetic data")
        from utils.datasets import generate_synthetic_network_data
        return generate_synthetic_network_data(n_normal=20000, n_anomalous=5000, seed=args.seed)

    X = np.concatenate(all_X, axis=0)
    y = np.concatenate(all_y, axis=0)

    # Shuffle
    rng = np.random.RandomState(args.seed)
    idx = rng.permutation(len(y))
    X = X[idx]
    y = y[idx]

    logger.info("Combined: %d samples (%d attack / %d benign)",
                len(y), int(y.sum()), int((y == 0).sum()))
    return X, y


def train(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    rng = np.random.RandomState(args.seed)

    logger.info("Loading data ...")
    X, y = load_data(args)
    splits = split_dataset(X, y, test_size=0.2, seed=args.seed)

    # Compute class balance
    n_pos = int(splits["y_train"].sum())
    n_neg = int((splits["y_train"] == 0).sum())
    scale_pos_weight = n_neg / max(n_pos, 1)
    logger.info("Train: %d pos / %d neg (scale_pos_weight=%.2f)", n_pos, n_neg, scale_pos_weight)

    model = lgb.LGBMClassifier(
        n_estimators=args.n_estimators,
        learning_rate=args.learning_rate,
        max_depth=args.max_depth,
        num_leaves=args.num_leaves,
        class_weight="balanced",
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,
        reg_lambda=0.1,
        random_state=args.seed,
        verbose=-1,
    )

    logger.info("Training LightGBM (%d estimators, max_depth=%d) ...",
                args.n_estimators, args.max_depth)
    model.fit(
        splits["X_train"], splits["y_train"],
        eval_set=[(splits["X_test"], splits["y_test"])],
        eval_metric=["auc", "binary_logloss"],
    )

    y_pred = model.predict(splits["X_test"])
    y_prob = model.predict_proba(splits["X_test"])[:, 1]

    evaluate_binary_classifier(
        splits["y_test"], y_pred, y_prob,
        model_name="network_lgbm", output_dir=output_dir,
    )

    # --- Export to ONNX ---
    onnx_path = output_dir / "network_anomaly.onnx"
    logger.info("Exporting to ONNX → %s", onnx_path)

    initial_type = [("input", FloatTensorType([None, NETWORK_FEATURE_COUNT]))]
    onnx_model = onnxmltools.convert_lightgbm(
        model, initial_types=initial_type, target_opset=15, zipmap=False,
    )
    onnxmltools.utils.save_model(onnx_model, str(onnx_path))
    logger.info("ONNX model saved (%d bytes)", onnx_path.stat().st_size)

    # Post-process: add Gather node to extract class 1 probability
    import onnx
    from onnx import helper, TensorProto

    m = onnx.load(str(onnx_path))

    # Find the probabilities output name from the last node
    prob_node_name = None
    for node in m.graph.node:
        if 'probabilities' in node.output:
            prob_node_name = node.output[0]
            break

    if prob_node_name:
        # Rename original probabilities output
        original_prob_name = prob_node_name + "_raw"
        for node in m.graph.node:
            for i, o in enumerate(node.output):
                if o == prob_node_name:
                    node.output[i] = original_prob_name

        # Add Gather node: extract [:, 1] from probabilities
        # First add constant for indices=[1]
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
            outputs=["anomaly_score"],
            name="extract_class1_proba",
            axis=1,
        )
        m.graph.node.append(gather_node)

        # Create new output for the anomaly score
        score_output = helper.make_tensor_value_info(
            "anomaly_score", TensorProto.FLOAT, [None, 1],
        )
        # Replace probabilities output with anomaly_score
        del m.graph.output[:]
        m.graph.output.extend([score_output])

    onnx.save(m, str(onnx_path))
    logger.info("ONNX graph modified: outputs -> anomaly_score")

    # Validate
    import onnxruntime as ort
    sess = ort.InferenceSession(str(onnx_path))
    for o in sess.get_outputs():
        logger.info("  Output '%s': shape=%s", o.name, o.shape)
    dummy = splits["X_test"][:5].astype(np.float32)
    out = sess.run(None, {"input": dummy})
    scores = np.array(out[0]).flatten()
    logger.info("  Score sample: %s", scores[:5].tolist())
    assert scores.min() >= 0.0 and scores.max() <= 1.0, "Scores out of [0,1] range"
    logger.info("ONNX validation passed ✓")
    logger.info("Training complete.")


if __name__ == "__main__":
    try:
        args = parse_args()
        train(args)
    except KeyboardInterrupt:
        logger.info("Interrupted")
        sys.exit(130)
    except Exception:
        logger.exception("Training failed")
        sys.exit(1)
