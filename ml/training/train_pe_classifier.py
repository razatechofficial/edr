#!/usr/bin/env python3
"""Train a LightGBM PE malware classifier and export to ONNX.

The model takes a 311-dimensional feature vector (matching the Go
``PEFeatureExtractor`` in ``internal/detection/ml/features/file.go``)
and outputs two values: P(benign) and P(malicious).

Usage:
    # Synthetic data (default):
    python train_pe_classifier.py --output-dir ./output

    # Real EMBER2018 vectorized features (see elastic/ember; needs tqdm + lief):
    python train_pe_classifier.py --ember-dir /data/ember2018 --output-dir ./output
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
import onnx
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

from utils.datasets import (
    generate_synthetic_pe_data,
    load_ember_dataset,
    split_dataset,
)
from utils.evaluation import (
    evaluate_binary_classifier,
    plot_feature_importance,
)
from utils.features import PEFeatureExtractor, TOTAL_FILE_FEATURES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("train_pe_classifier")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train PE malware classifier (LightGBM)")
    p.add_argument("--ember-dir", type=str, default=None, help="Path to EMBER2018 directory (X_train.dat / y_train.dat)")
    p.add_argument("--n-benign", type=int, default=10000, help="Synthetic benign samples")
    p.add_argument("--n-malicious", type=int, default=10000, help="Synthetic malicious samples")
    p.add_argument("--output-dir", type=str, default="./output", help="Directory for output artifacts")
    p.add_argument("--n-estimators", type=int, default=500, help="Number of boosting rounds")
    p.add_argument("--learning-rate", type=float, default=0.05, help="Learning rate")
    p.add_argument("--max-depth", type=int, default=8, help="Max tree depth")
    p.add_argument("--num-leaves", type=int, default=64, help="Number of leaves per tree")
    p.add_argument("--seed", type=int, default=42, help="Random seed")
    return p.parse_args()


def load_data(args: argparse.Namespace) -> tuple[np.ndarray, np.ndarray]:
    if args.ember_dir:
        logger.info("Loading EMBER dataset from %s …", args.ember_dir)
        X, y = load_ember_dataset(args.ember_dir)
        if X.shape[1] != TOTAL_FILE_FEATURES:
            logger.warning(
                "EMBER feature dim %d ≠ expected %d; padding/truncating",
                X.shape[1], TOTAL_FILE_FEATURES,
            )
            if X.shape[1] < TOTAL_FILE_FEATURES:
                pad = np.zeros((X.shape[0], TOTAL_FILE_FEATURES - X.shape[1]), dtype=np.float32)
                X = np.hstack([X, pad])
            else:
                X = X[:, :TOTAL_FILE_FEATURES]
    else:
        logger.info(
            "Generating synthetic PE data (%d benign, %d malicious) …",
            args.n_benign, args.n_malicious,
        )
        X, y = generate_synthetic_pe_data(
            n_benign=args.n_benign,
            n_malicious=args.n_malicious,
            seed=args.seed,
        )
    logger.info("Dataset: %d samples, %d features", X.shape[0], X.shape[1])
    return X, y


def train(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    X, y = load_data(args)
    splits = split_dataset(X, y, seed=args.seed)

    logger.info(
        "Split sizes — train: %d, val: %d, test: %d",
        len(splits["y_train"]),
        len(splits["y_val"]),
        len(splits["y_test"]),
    )

    model = lgb.LGBMClassifier(
        n_estimators=args.n_estimators,
        learning_rate=args.learning_rate,
        max_depth=args.max_depth,
        num_leaves=args.num_leaves,
        objective="binary",
        metric="binary_logloss",
        class_weight="balanced",
        random_state=args.seed,
        n_jobs=-1,
        verbose=-1,
    )

    logger.info("Training LightGBM classifier …")
    model.fit(
        splits["X_train"],
        splits["y_train"],
        eval_set=[(splits["X_val"], splits["y_val"])],
        callbacks=[lgb.log_evaluation(period=50)],
    )

    y_pred = model.predict(splits["X_test"])
    y_prob = model.predict_proba(splits["X_test"])[:, 1]

    metrics = evaluate_binary_classifier(
        splits["y_test"],
        y_pred,
        y_prob,
        model_name="pe_classifier",
        output_dir=output_dir,
    )

    feature_names = PEFeatureExtractor.feature_names()
    plot_feature_importance(
        model.feature_importances_,
        feature_names,
        model_name="pe_classifier",
        top_n=30,
        save_path=output_dir / "pe_classifier_feature_importance.png",
    )

    # --- Export to ONNX ---
    onnx_path = output_dir / "pe_classifier.onnx"
    logger.info("Exporting to ONNX → %s", onnx_path)

    initial_type = [("input", FloatTensorType([None, TOTAL_FILE_FEATURES]))]
    onnx_model = onnxmltools.convert_lightgbm(
        model,
        initial_types=initial_type,
        target_opset=15,
    )

    onnx_model.graph.input[0].name = "input"
    for node in onnx_model.graph.node:
        for j, inp in enumerate(node.input):
            if inp == onnx_model.graph.input[0].name or inp == "input":
                continue
    if len(onnx_model.graph.output) >= 2:
        onnx_model.graph.output[0].name = "label"
        onnx_model.graph.output[1].name = "probabilities"

    onnx.save(onnx_model, str(onnx_path))
    logger.info("ONNX model saved (%d bytes)", onnx_path.stat().st_size)

    _validate_onnx(onnx_path, splits["X_test"][:5])

    logger.info("Training complete.  Metrics: precision=%.4f  recall=%.4f  F1=%.4f  AUC=%.4f",
                metrics["precision"], metrics["recall"], metrics["f1"], metrics.get("roc_auc", 0))


def _validate_onnx(onnx_path: Path, sample_input: np.ndarray) -> None:
    import onnxruntime as ort

    logger.info("Validating ONNX model with onnxruntime …")
    sess = ort.InferenceSession(str(onnx_path))
    input_name = sess.get_inputs()[0].name
    output_names = [o.name for o in sess.get_outputs()]
    results = sess.run(output_names, {input_name: sample_input.astype(np.float32)})
    logger.info("  Input shape: %s", sample_input.shape)
    for name, arr in zip(output_names, results):
        arr_np = np.array(arr)
        logger.info("  Output '%s': shape=%s, sample=%s", name, arr_np.shape, arr_np[:2])
    logger.info("ONNX validation passed ✓")


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
