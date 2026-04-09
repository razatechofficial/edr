"""Unified training CLI entry point.

Usage:
    python -m training train --model pe --data ./data/ember --output ./models
    python -m training train --model behavior --data ./data/cape --epochs 50
    python -m training retrain --model pe --base ./models/pe_classifier.onnx --data ./data/new
    python -m training export --format onnx --input ./checkpoints --output ./models
    python -m training validate --model-dir ./models
    python -m training sign --model ./models --key ./keys/signing.key
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
log = logging.getLogger("training")


def cmd_train(args: argparse.Namespace) -> None:
    """Train a model from scratch."""
    model = args.model
    data_dir = args.data
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    if model == "pe":
        from train_pe_classifier import main as train_pe
        sys.argv = [
            "train_pe_classifier.py",
            "--data-dir", data_dir,
            "--output-dir", str(output),
            "--n-estimators", str(args.n_estimators),
        ]
        if args.synthetic:
            sys.argv.append("--synthetic")
        train_pe()

    elif model == "behavior":
        from train_behavior_lstm import main as train_behavior
        sys.argv = [
            "train_behavior_lstm.py",
            "--output-dir", str(output),
            "--epochs", str(args.epochs),
        ]
        if data_dir:
            sys.argv.extend(["--data-dir", data_dir])
        train_behavior()

    elif model == "network":
        from train_network_anomaly import main as train_network
        sys.argv = [
            "train_network_anomaly.py",
            "--output-dir", str(output),
            "--epochs", str(args.epochs),
        ]
        if data_dir:
            sys.argv.extend(["--data-dir", data_dir])
        train_network()

    elif model == "ransomware":
        from train_ransomware import main as train_ransomware
        sys.argv = [
            "train_ransomware.py",
            "--output-dir", str(output),
        ]
        if data_dir:
            sys.argv.extend(["--data-dir", data_dir])
        if args.synthetic:
            sys.argv.append("--synthetic")
        train_ransomware()

    else:
        log.error("Unknown model: %s (choices: pe, behavior, network, ransomware)", model)
        sys.exit(1)

    log.info("Training complete for model '%s'", model)


def cmd_retrain(args: argparse.Namespace) -> None:
    """Retrain an existing model with new data (transfer learning)."""
    model = args.model
    base_path = args.base
    data_dir = args.data
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    log.info("Retraining %s from base %s with data from %s", model, base_path, data_dir)

    if model == "pe":
        from train_pe_classifier import main as train_pe
        sys.argv = [
            "train_pe_classifier.py",
            "--data-dir", data_dir,
            "--output-dir", str(output),
            "--n-estimators", str(args.n_estimators),
        ]
        train_pe()
    elif model in ("behavior", "network"):
        cmd_train(args)
    else:
        log.error("Retrain not supported for model: %s", model)
        sys.exit(1)


def cmd_export(args: argparse.Namespace) -> None:
    """Export trained checkpoints to ONNX format."""
    from export_onnx import main as export_main
    sys.argv = ["export_onnx.py"]
    if args.input_dir:
        sys.argv.extend(["validate", "--model-dir", args.input_dir])
    export_main()


def cmd_validate(args: argparse.Namespace) -> None:
    """Validate ONNX models in a directory."""
    from export_onnx import cmd_validate as validate_fn
    validate_fn(args)


def cmd_sign(args: argparse.Namespace) -> None:
    """Sign all ONNX models in a directory."""
    from sign_models import sign_directory
    sign_directory(Path(args.model), Path(args.key))


def main() -> None:
    p = argparse.ArgumentParser(
        prog="python -m training",
        description="EDR ML training pipeline",
    )
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("train", help="Train a model from scratch")
    t.add_argument("--model", required=True,
                   choices=["pe", "behavior", "network", "ransomware"])
    t.add_argument("--data", default="./data")
    t.add_argument("--output", default="./models")
    t.add_argument("--epochs", type=int, default=50)
    t.add_argument("--n-estimators", type=int, default=500)
    t.add_argument("--synthetic", action="store_true")

    r = sub.add_parser("retrain", help="Retrain with new data")
    r.add_argument("--model", required=True)
    r.add_argument("--base", required=True, help="Path to base ONNX model")
    r.add_argument("--data", required=True)
    r.add_argument("--output", default="./models")
    r.add_argument("--epochs", type=int, default=20)
    r.add_argument("--n-estimators", type=int, default=200)

    e = sub.add_parser("export", help="Export checkpoints to ONNX")
    e.add_argument("--format", default="onnx")
    e.add_argument("--input-dir", default="")
    e.add_argument("--output", default="./models")

    v = sub.add_parser("validate", help="Validate ONNX models")
    v.add_argument("--model-dir", required=True)

    s = sub.add_parser("sign", help="Sign ONNX models")
    s.add_argument("--model", required=True, help="Path to models dir or single model")
    s.add_argument("--key", required=True, help="Path to Ed25519 private key")

    args = p.parse_args()
    dispatch = {
        "train": cmd_train,
        "retrain": cmd_retrain,
        "export": cmd_export,
        "validate": cmd_validate,
        "sign": cmd_sign,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
