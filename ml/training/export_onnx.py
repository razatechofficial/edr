#!/usr/bin/env python3
"""Utility to convert trained models to ONNX, validate with onnxruntime,
and run test inference with sample inputs.

This can re-export or validate models that were already exported by the
individual training scripts.

Usage:
    # Validate all .onnx files in a directory:
    python export_onnx.py validate --model-dir ./output

    # Re-export a LightGBM model:
    python export_onnx.py export-lgbm --model-path ./model.txt --output ./pe_classifier.onnx --input-dim 311

    # Re-export a PyTorch model:
    python export_onnx.py export-torch --model-path ./behavior_lstm_best.pt --output ./behavior_lstm.onnx

    # Run sample inference on an ONNX model:
    python export_onnx.py infer --onnx-path ./output/pe_classifier.onnx --input-dim 311
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("export_onnx")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_model(onnx_path: Path) -> bool:
    """Load, check, and run a quick inference on an ONNX model."""
    logger.info("Validating %s …", onnx_path)
    try:
        model = onnx.load(str(onnx_path))
        onnx.checker.check_model(model)
    except Exception as exc:
        logger.error("  ONNX checker failed: %s", exc)
        return False

    try:
        sess = ort.InferenceSession(str(onnx_path))
    except Exception as exc:
        logger.error("  ORT session creation failed: %s", exc)
        return False

    inputs = sess.get_inputs()
    outputs = sess.get_outputs()
    logger.info("  Inputs:")
    for inp in inputs:
        logger.info("    %s: shape=%s, type=%s", inp.name, inp.shape, inp.type)
    logger.info("  Outputs:")
    for out in outputs:
        logger.info("    %s: shape=%s, type=%s", out.name, out.shape, out.type)

    # Build dummy input matching declared shapes.
    feed: dict[str, np.ndarray] = {}
    for inp in inputs:
        shape = []
        for d in inp.shape:
            shape.append(d if isinstance(d, int) else 1)
        feed[inp.name] = np.random.randn(*shape).astype(np.float32)

    try:
        results = sess.run([o.name for o in outputs], feed)
        for out, arr in zip(outputs, results):
            arr_np = np.array(arr)
            logger.info("    %s → shape=%s, sample=%s", out.name, arr_np.shape, arr_np.flat[:4])
    except Exception as exc:
        logger.error("  Inference failed: %s", exc)
        return False

    size_mb = onnx_path.stat().st_size / (1024 * 1024)
    logger.info("  Model size: %.2f MB", size_mb)
    logger.info("  Validation passed ✓")
    return True


def cmd_validate(args: argparse.Namespace) -> None:
    model_dir = Path(args.model_dir)
    onnx_files = sorted(model_dir.glob("*.onnx"))
    if not onnx_files:
        logger.error("No .onnx files found in %s", model_dir)
        sys.exit(1)

    results: dict[str, bool] = {}
    for p in onnx_files:
        results[p.name] = validate_model(p)

    logger.info("\n=== Validation Summary ===")
    all_ok = True
    for name, ok in results.items():
        status = "PASS" if ok else "FAIL"
        logger.info("  %-30s %s", name, status)
        if not ok:
            all_ok = False

    if not all_ok:
        sys.exit(1)


# ---------------------------------------------------------------------------
# LightGBM / XGBoost re-export
# ---------------------------------------------------------------------------


def cmd_export_lgbm(args: argparse.Namespace) -> None:
    import lightgbm as lgb
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType

    model_path = Path(args.model_path)
    logger.info("Loading LightGBM model from %s …", model_path)
    model = lgb.Booster(model_file=str(model_path))

    initial_type = [("input", FloatTensorType([None, args.input_dim]))]
    onnx_model = onnxmltools.convert_lightgbm(model, initial_types=initial_type, target_opset=15)
    onnx_model.graph.input[0].name = "input"

    output_path = Path(args.output)
    onnx.save(onnx_model, str(output_path))
    logger.info("Saved → %s (%d bytes)", output_path, output_path.stat().st_size)
    validate_model(output_path)


def cmd_export_xgb(args: argparse.Namespace) -> None:
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType
    from xgboost import XGBClassifier

    model_path = Path(args.model_path)
    logger.info("Loading XGBoost model from %s …", model_path)
    model = XGBClassifier()
    model.load_model(str(model_path))

    initial_type = [("input", FloatTensorType([None, args.input_dim]))]
    onnx_model = onnxmltools.convert_xgboost(model, initial_types=initial_type, target_opset=15)
    onnx_model.graph.input[0].name = "input"

    output_path = Path(args.output)
    onnx.save(onnx_model, str(output_path))
    logger.info("Saved → %s (%d bytes)", output_path, output_path.stat().st_size)
    validate_model(output_path)


def cmd_export_torch(args: argparse.Namespace) -> None:
    """Re-export a PyTorch model checkpoint to ONNX.

    Requires the model class to be importable.  Defaults to BehaviorLSTM.
    """
    import torch

    model_path = Path(args.model_path)
    output_path = Path(args.output)
    logger.info("Loading PyTorch state dict from %s …", model_path)

    if args.model_class == "behavior_lstm":
        from train_behavior_lstm import BehaviorLSTM
        model = BehaviorLSTM(
            input_dim=args.input_features,
            hidden_dim=args.hidden_dim,
            num_layers=args.num_layers,
        )
        dummy = torch.randn(1, args.seq_len, args.input_features)
        in_names = ["input"]
        out_names = ["score"]
        dynamic = {"input": {0: "batch"}, "score": {0: "batch"}}
    elif args.model_class == "network_anomaly":
        from train_network_anomaly import AnomalyScorer, NetworkAutoencoder
        ae = NetworkAutoencoder(input_dim=args.input_features, latent_dim=args.latent_dim)
        model = AnomalyScorer(ae)
        dummy = torch.randn(1, args.input_features)
        in_names = ["input"]
        out_names = ["anomaly_score"]
        dynamic = {"input": {0: "batch"}, "anomaly_score": {0: "batch"}}
    else:
        logger.error("Unknown model class: %s", args.model_class)
        sys.exit(1)

    model.load_state_dict(torch.load(str(model_path), weights_only=True))
    model.eval()

    torch.onnx.export(
        model, dummy, str(output_path),
        input_names=in_names,
        output_names=out_names,
        dynamic_axes=dynamic,
        opset_version=15,
    )
    logger.info("Saved → %s (%d bytes)", output_path, output_path.stat().st_size)
    validate_model(output_path)


# ---------------------------------------------------------------------------
# Sample inference
# ---------------------------------------------------------------------------


def cmd_infer(args: argparse.Namespace) -> None:
    onnx_path = Path(args.onnx_path)
    if not onnx_path.exists():
        logger.error("Model not found: %s", onnx_path)
        sys.exit(1)

    sess = ort.InferenceSession(str(onnx_path))
    inputs = sess.get_inputs()
    outputs = sess.get_outputs()

    feed: dict[str, np.ndarray] = {}
    for inp in inputs:
        shape = []
        for d in inp.shape:
            shape.append(d if isinstance(d, int) else args.batch_size)
        arr = np.random.randn(*shape).astype(np.float32)
        feed[inp.name] = arr
        logger.info("Input '%s': shape=%s", inp.name, arr.shape)

    results = sess.run([o.name for o in outputs], feed)
    for out, arr in zip(outputs, results):
        arr_np = np.array(arr)
        logger.info("Output '%s': shape=%s", out.name, arr_np.shape)
        logger.info("  values: %s", arr_np)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser(description="ONNX export & validation utility")
    sub = p.add_subparsers(dest="command", required=True)

    # validate
    v = sub.add_parser("validate", help="Validate ONNX models in a directory")
    v.add_argument("--model-dir", type=str, required=True)

    # export-lgbm
    el = sub.add_parser("export-lgbm", help="Re-export LightGBM model to ONNX")
    el.add_argument("--model-path", type=str, required=True)
    el.add_argument("--output", type=str, required=True)
    el.add_argument("--input-dim", type=int, required=True)

    # export-xgb
    ex = sub.add_parser("export-xgb", help="Re-export XGBoost model to ONNX")
    ex.add_argument("--model-path", type=str, required=True)
    ex.add_argument("--output", type=str, required=True)
    ex.add_argument("--input-dim", type=int, required=True)

    # export-torch
    et = sub.add_parser("export-torch", help="Re-export PyTorch model to ONNX")
    et.add_argument("--model-path", type=str, required=True)
    et.add_argument("--output", type=str, required=True)
    et.add_argument("--model-class", type=str, default="behavior_lstm",
                    choices=["behavior_lstm", "network_anomaly"])
    et.add_argument("--input-features", type=int, default=48)
    et.add_argument("--seq-len", type=int, default=50)
    et.add_argument("--hidden-dim", type=int, default=128)
    et.add_argument("--num-layers", type=int, default=2)
    et.add_argument("--latent-dim", type=int, default=4)

    # infer
    inf = sub.add_parser("infer", help="Run sample inference on an ONNX model")
    inf.add_argument("--onnx-path", type=str, required=True)
    inf.add_argument("--batch-size", type=int, default=3)

    args = p.parse_args()
    dispatch = {
        "validate": cmd_validate,
        "export-lgbm": cmd_export_lgbm,
        "export-xgb": cmd_export_xgb,
        "export-torch": cmd_export_torch,
        "infer": cmd_infer,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        logger.exception("Failed")
        sys.exit(1)
