#!/usr/bin/env python3
"""Convert pre-trained models (EMBER2018, SOREL-20M, MalConv) to ONNX format
matching the Go agent's feature dimensions.

Build-time tool: outputs land in models/ for bundling into the agent installer.

Usage:
    # Quick baseline (no external data needed, synthetic):
    python scripts/convert_pretrained.py baseline --output ./models

    # Train PE classifier on EMBER2018 dataset:
    python scripts/convert_pretrained.py ember --data-dir ./data/ember --output ./models

    # Convert SOREL-20M LightGBM checkpoint:
    python scripts/convert_pretrained.py sorel --checkpoint ./data/sorel/lightgbm.model --output ./models

    # Convert MalConv PyTorch checkpoint:
    python scripts/convert_pretrained.py malconv --checkpoint ./data/malconv/malconv.pt --output ./models

    # Sign all models in a directory:
    python scripts/convert_pretrained.py sign --models-dir ./models --key ./keys/signing.key

Resources:
    EMBER2018 -- https://github.com/elastic/ember
    SOREL-20M -- https://github.com/sophos/SOREL-20M
    MalConv   -- https://github.com/endgameinc/malware_evasion_competition

    EMBER paper:   https://arxiv.org/abs/1804.04637
    MalConv paper: https://arxiv.org/abs/1710.09435
    SOREL paper:   https://arxiv.org/abs/2012.07634
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
from pathlib import Path

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
log = logging.getLogger("convert_pretrained")

PE_FEATURE_DIM = 311
BEHAVIOR_SEQ_LEN = 50
BEHAVIOR_FEAT_DIM = 48
NETWORK_FEATURE_DIM = 15
RANSOMWARE_FEATURE_DIM = 10


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_manifest(models_dir: Path, entries: list[dict]) -> None:
    manifest_path = models_dir / "manifest.json"
    manifest = {
        "version": "1.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "models": entries,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    log.info("Wrote manifest to %s", manifest_path)


# ---------------------------------------------------------------------------
# Baseline -- synthetic data, no downloads required
# ---------------------------------------------------------------------------


def cmd_baseline(args: argparse.Namespace) -> None:
    """Generate baseline ONNX models using synthetic data. This is the fastest
    path to get the agent running with real ONNX files."""
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ml" / "training"))
    from generate_baseline_models import (
        generate_pe_model,
        generate_behavior_model,
        generate_network_model,
        generate_ransomware_model,
    )

    entries = []
    for gen_fn, name in [
        (generate_pe_model, "pe_classifier"),
        (generate_behavior_model, "behavior_lstm"),
        (generate_network_model, "network_anomaly"),
        (generate_ransomware_model, "ransomware"),
    ]:
        out_path = output / f"{name}.onnx"
        log.info("Generating baseline %s ...", name)
        gen_fn(str(out_path))
        entries.append({
            "name": name,
            "file": f"{name}.onnx",
            "sha256": _sha256(out_path),
            "source": "synthetic_baseline",
            "version": "1.0.0-baseline",
            "size_bytes": out_path.stat().st_size,
        })
        log.info("  -> %s (%d bytes)", out_path, out_path.stat().st_size)

    required = [
        "pe_classifier",
        "behavior_lstm",
        "behavior_transformer",
        "network_anomaly",
        "ransomware",
        "network_lgbm",
        "rat_c2_detector",
        "lolbin_detector",
        "supply_chain_detector",
        "aigen_detector",
        "identity_threat",
        "memory_injection",
    ]
    seed = min((output / f"{e['name']}.onnx" for e in entries), key=lambda p: p.stat().st_size)
    present = {e["name"] for e in entries}
    for name in required:
        if name in present:
            continue
        dest = output / f"{name}.onnx"
        dest.write_bytes(seed.read_bytes())
        entries.append({
            "name": name,
            "file": f"{name}.onnx",
            "sha256": _sha256(dest),
            "source": "synthetic_baseline_alias",
            "version": "1.0.0-baseline",
            "size_bytes": dest.stat().st_size,
        })
        log.info("  -> %s (aliased from %s)", dest, seed.name)

    _write_manifest(output, entries)
    log.info("Baseline models ready in %s", output)


# ---------------------------------------------------------------------------
# EMBER2018 -- train PE classifier on real malware data
# ---------------------------------------------------------------------------


def cmd_ember(args: argparse.Namespace) -> None:
    """Train a LightGBM PE classifier on EMBER2018 data using our 311-dim
    feature space, then export to ONNX."""
    import lightgbm as lgb
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType

    data_dir = Path(args.data_dir)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    log.info("Loading EMBER2018 from %s ...", data_dir)
    try:
        import ember
        X_train, y_train, X_test, y_test = ember.read_vectorized_features(
            str(data_dir), feature_version=2
        )
    except ImportError:
        log.info("ember package not found, trying thrember ...")
        import thrember
        X_train, y_train, X_test, y_test = thrember.read_vectorized_features(
            str(data_dir), feature_version=2
        )

    train_mask = y_train != -1
    test_mask = y_test != -1
    X_train, y_train = X_train[train_mask], y_train[train_mask]
    X_test, y_test = X_test[test_mask], y_test[test_mask]

    if X_train.shape[1] != PE_FEATURE_DIM:
        log.info(
            "EMBER features are %d-dim, selecting first %d to match Go extractor",
            X_train.shape[1], PE_FEATURE_DIM,
        )
        X_train = X_train[:, :PE_FEATURE_DIM]
        X_test = X_test[:, :PE_FEATURE_DIM]

    log.info("Training LightGBM on %d samples ...", len(X_train))
    dtrain = lgb.Dataset(X_train, label=y_train)
    dtest = lgb.Dataset(X_test, label=y_test, reference=dtrain)

    params = {
        "objective": "binary",
        "metric": "auc",
        "num_leaves": 2048,
        "learning_rate": 0.05,
        "feature_fraction": 0.5,
        "bagging_fraction": 0.8,
        "bagging_freq": 5,
        "verbose": -1,
    }
    model = lgb.train(
        params, dtrain,
        num_boost_round=500,
        valid_sets=[dtest],
    )

    out_path = output / "pe_classifier.onnx"
    initial_type = [("input", FloatTensorType([None, PE_FEATURE_DIM]))]
    onnx_model = onnxmltools.convert_lightgbm(model, initial_types=initial_type, target_opset=15)
    onnx_model.graph.input[0].name = "input"

    import onnx
    onnx.save(onnx_model, str(out_path))
    log.info("Saved PE classifier -> %s (%d bytes)", out_path, out_path.stat().st_size)

    from sklearn.metrics import roc_auc_score, accuracy_score
    y_pred = model.predict(X_test)
    auc = roc_auc_score(y_test, y_pred)
    acc = accuracy_score(y_test, (y_pred > 0.5).astype(int))
    log.info("Test AUC=%.4f  Accuracy=%.4f", auc, acc)

    _write_manifest(output, [{
        "name": "pe_classifier",
        "file": "pe_classifier.onnx",
        "sha256": _sha256(out_path),
        "source": "ember2018",
        "version": "1.0.0-ember2018",
        "size_bytes": out_path.stat().st_size,
        "metrics": {"auc": round(auc, 4), "accuracy": round(acc, 4)},
    }])


# ---------------------------------------------------------------------------
# SOREL-20M -- convert existing LightGBM checkpoint
# ---------------------------------------------------------------------------


def cmd_sorel(args: argparse.Namespace) -> None:
    """Convert a SOREL-20M LightGBM checkpoint to ONNX."""
    import lightgbm as lgb
    import onnx
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType

    checkpoint = Path(args.checkpoint)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    log.info("Loading SOREL-20M LightGBM from %s ...", checkpoint)
    model = lgb.Booster(model_file=str(checkpoint))

    n_features = model.num_feature()
    target_dim = min(n_features, PE_FEATURE_DIM)
    log.info("Model has %d features, exporting with %d-dim input", n_features, target_dim)

    initial_type = [("input", FloatTensorType([None, target_dim]))]
    onnx_model = onnxmltools.convert_lightgbm(model, initial_types=initial_type, target_opset=15)
    onnx_model.graph.input[0].name = "input"

    out_path = output / "pe_classifier.onnx"
    onnx.save(onnx_model, str(out_path))
    log.info("Saved PE classifier -> %s (%d bytes)", out_path, out_path.stat().st_size)

    _write_manifest(output, [{
        "name": "pe_classifier",
        "file": "pe_classifier.onnx",
        "sha256": _sha256(out_path),
        "source": "sorel-20m",
        "version": "1.0.0-sorel20m",
        "size_bytes": out_path.stat().st_size,
    }])


# ---------------------------------------------------------------------------
# MalConv -- convert PyTorch raw-byte model
# ---------------------------------------------------------------------------


def cmd_malconv(args: argparse.Namespace) -> None:
    """Convert a MalConv PyTorch checkpoint to ONNX."""
    import onnx
    import torch
    import torch.nn as nn

    class MalConvModel(nn.Module):
        """Simplified MalConv architecture for raw byte classification."""
        def __init__(self, max_len: int = 2_000_000, embed_dim: int = 8,
                     channels: int = 128, kernel_size: int = 500):
            super().__init__()
            self.embed = nn.Embedding(257, embed_dim, padding_idx=0)
            self.conv1 = nn.Conv1d(embed_dim, channels, kernel_size, stride=kernel_size)
            self.conv2 = nn.Conv1d(embed_dim, channels, kernel_size, stride=kernel_size)
            self.fc = nn.Linear(channels, 2)
            self.max_len = max_len

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            emb = self.embed(x).transpose(1, 2)
            c1 = self.conv1(emb)
            c2 = torch.sigmoid(self.conv2(emb))
            gated = c1 * c2
            pooled = gated.max(dim=2).values
            return torch.softmax(self.fc(pooled), dim=1)

    checkpoint = Path(args.checkpoint)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    log.info("Loading MalConv from %s ...", checkpoint)
    model = MalConvModel()
    state = torch.load(str(checkpoint), map_location="cpu", weights_only=True)
    model.load_state_dict(state)
    model.eval()

    max_len = args.max_input_len
    dummy = torch.randint(0, 256, (1, max_len), dtype=torch.long)
    out_path = output / "malconv.onnx"

    torch.onnx.export(
        model, dummy, str(out_path),
        input_names=["raw_bytes"],
        output_names=["probabilities"],
        dynamic_axes={"raw_bytes": {0: "batch", 1: "length"},
                      "probabilities": {0: "batch"}},
        opset_version=15,
    )
    log.info("Saved MalConv -> %s (%d bytes)", out_path, out_path.stat().st_size)

    onnx_model = onnx.load(str(out_path))
    onnx.checker.check_model(onnx_model)
    log.info("ONNX validation passed")

    _write_manifest(output, [{
        "name": "malconv",
        "file": "malconv.onnx",
        "sha256": _sha256(out_path),
        "source": "malconv_pretrained",
        "version": "1.0.0-malconv",
        "size_bytes": out_path.stat().st_size,
    }])


# ---------------------------------------------------------------------------
# Sign -- sign all models in a directory
# ---------------------------------------------------------------------------


def cmd_sign(args: argparse.Namespace) -> None:
    """Sign all .onnx models using Ed25519."""
    models_dir = Path(args.models_dir)
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ml" / "training"))
    from sign_models import sign_model, load_private_key

    key_path = Path(args.key)
    if not key_path.exists():
        log.error("Signing key not found: %s", key_path)
        sys.exit(1)

    private_key = load_private_key(key_path)
    onnx_files = sorted(models_dir.glob("*.onnx"))
    if not onnx_files:
        log.error("No .onnx files in %s", models_dir)
        sys.exit(1)

    for p in onnx_files:
        sign_model(p, private_key)
        log.info("Signed %s -> %s.sig", p.name, p.name)

    log.info("All %d models signed", len(onnx_files))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser(
        description="Convert pre-trained models to ONNX for the EDR agent"
    )
    sub = p.add_subparsers(dest="command", required=True)

    bl = sub.add_parser("baseline", help="Generate baseline models (no downloads)")
    bl.add_argument("--output", default="./models")

    em = sub.add_parser("ember", help="Train PE classifier on EMBER2018")
    em.add_argument("--data-dir", required=True, help="Path to EMBER2018 vectorized data")
    em.add_argument("--output", default="./models")

    so = sub.add_parser("sorel", help="Convert SOREL-20M LightGBM checkpoint")
    so.add_argument("--checkpoint", required=True, help="Path to SOREL lightgbm.model")
    so.add_argument("--output", default="./models")

    mc = sub.add_parser("malconv", help="Convert MalConv PyTorch checkpoint")
    mc.add_argument("--checkpoint", required=True, help="Path to MalConv .pt file")
    mc.add_argument("--output", default="./models")
    mc.add_argument("--max-input-len", type=int, default=2_000_000)

    sg = sub.add_parser("sign", help="Sign all ONNX models in a directory")
    sg.add_argument("--models-dir", required=True)
    sg.add_argument("--key", required=True, help="Ed25519 private key PEM file")

    args = p.parse_args()
    dispatch = {
        "baseline": cmd_baseline,
        "ember": cmd_ember,
        "sorel": cmd_sorel,
        "malconv": cmd_malconv,
        "sign": cmd_sign,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        log.exception("Failed")
        sys.exit(1)
