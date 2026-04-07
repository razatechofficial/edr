#!/usr/bin/env python3
"""Train an XGBoost classifier for ransomware detection.

Input:  (batch, 10) — 10 ransomware indicator features matching
        ``ransomwareFeatureKeys`` in ``internal/detection/ml/engine.go``
Output: (batch, 1) — ransomware probability ∈ [0, 1]

Feature keys (in order):
    entropy_increase_rate, file_rename_rate, file_delete_rate,
    file_type_change_rate, known_extension_append, ransom_note_similarity,
    shadow_copy_deletion, encryption_api_calls, network_beacon_rate,
    unique_file_extensions

Usage:
    python train_ransomware.py --output-dir ./output
    python train_ransomware.py --data-path /data/ransomware.csv --output-dir ./output
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import onnx
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
from xgboost import XGBClassifier

from utils.datasets import generate_synthetic_ransomware_data, split_dataset
from utils.evaluation import evaluate_binary_classifier, plot_feature_importance
from utils.features import RANSOMWARE_FEATURE_COUNT, RANSOMWARE_FEATURE_KEYS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("train_ransomware")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train ransomware XGBoost classifier")
    p.add_argument("--data-path", type=str, default=None, help="Path to ransomware CSV (label + 10 features)")
    p.add_argument("--n-benign", type=int, default=8000, help="Synthetic benign samples")
    p.add_argument("--n-ransomware", type=int, default=5000, help="Synthetic ransomware samples")
    p.add_argument("--output-dir", type=str, default="./output")
    p.add_argument("--n-estimators", type=int, default=300)
    p.add_argument("--max-depth", type=int, default=6)
    p.add_argument("--learning-rate", type=float, default=0.1)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def load_data(args: argparse.Namespace) -> tuple[np.ndarray, np.ndarray]:
    if args.data_path:
        logger.info("Loading ransomware data from %s …", args.data_path)
        import pandas as pd

        df = pd.read_csv(args.data_path)
        y = df.iloc[:, 0].values.astype(np.int32)
        X = df.iloc[:, 1:].values.astype(np.float32)
        if X.shape[1] != RANSOMWARE_FEATURE_COUNT:
            logger.warning(
                "Feature dim %d ≠ expected %d", X.shape[1], RANSOMWARE_FEATURE_COUNT,
            )
        return X, y

    logger.info(
        "Generating synthetic ransomware data (%d benign, %d ransomware) …",
        args.n_benign, args.n_ransomware,
    )
    return generate_synthetic_ransomware_data(
        n_benign=args.n_benign,
        n_ransomware=args.n_ransomware,
        seed=args.seed,
    )


def train(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    X, y = load_data(args)
    splits = split_dataset(X, y, seed=args.seed)

    logger.info(
        "Split sizes — train: %d, val: %d, test: %d",
        len(splits["y_train"]), len(splits["y_val"]), len(splits["y_test"]),
    )

    n_pos = splits["y_train"].sum()
    n_neg = len(splits["y_train"]) - n_pos
    scale_pos_weight = n_neg / max(n_pos, 1)

    model = XGBClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        scale_pos_weight=scale_pos_weight,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=args.seed,
        use_label_encoder=False,
        n_jobs=-1,
        verbosity=1,
    )

    logger.info("Training XGBoost classifier …")
    model.fit(
        splits["X_train"],
        splits["y_train"],
        eval_set=[(splits["X_val"], splits["y_val"])],
        verbose=50,
    )

    y_pred = model.predict(splits["X_test"])
    y_prob = model.predict_proba(splits["X_test"])[:, 1]

    metrics = evaluate_binary_classifier(
        splits["y_test"], y_pred, y_prob,
        model_name="ransomware", output_dir=output_dir,
    )

    plot_feature_importance(
        model.feature_importances_,
        list(RANSOMWARE_FEATURE_KEYS),
        model_name="ransomware",
        top_n=RANSOMWARE_FEATURE_COUNT,
        save_path=output_dir / "ransomware_feature_importance.png",
    )

    # --- Export to ONNX ---
    onnx_path = output_dir / "ransomware.onnx"
    logger.info("Exporting to ONNX → %s", onnx_path)

    initial_type = [("input", FloatTensorType([None, RANSOMWARE_FEATURE_COUNT]))]
    onnx_model = onnxmltools.convert_xgboost(
        model,
        initial_types=initial_type,
        target_opset=15,
    )

    onnx_model.graph.input[0].name = "input"
    if len(onnx_model.graph.output) >= 2:
        onnx_model.graph.output[0].name = "label"
        onnx_model.graph.output[1].name = "probabilities"
    elif len(onnx_model.graph.output) == 1:
        onnx_model.graph.output[0].name = "score"

    onnx.save(onnx_model, str(onnx_path))
    logger.info("ONNX model saved (%d bytes)", onnx_path.stat().st_size)

    _validate_onnx(onnx_path, splits["X_test"][:5])

    logger.info(
        "Training complete.  Metrics: precision=%.4f  recall=%.4f  F1=%.4f  AUC=%.4f",
        metrics["precision"], metrics["recall"], metrics["f1"], metrics.get("roc_auc", 0),
    )


def _validate_onnx(onnx_path: Path, sample_input: np.ndarray) -> None:
    import onnxruntime as ort

    logger.info("Validating ONNX model …")
    sess = ort.InferenceSession(str(onnx_path))
    input_name = sess.get_inputs()[0].name
    output_names = [o.name for o in sess.get_outputs()]
    results = sess.run(output_names, {input_name: sample_input.astype(np.float32)})
    for name, arr in zip(output_names, results):
        arr_np = np.array(arr)
        logger.info("  Output '%s': shape=%s, sample=%s", name, arr_np.shape, arr_np[:3])
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
