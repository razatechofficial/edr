#!/usr/bin/env python3
"""Audit all 12 ONNX models: input/output shapes, dtypes, score ranges, size."""
import json
import logging
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("audit")

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"
MODEL_NAMES = [
    "pe_classifier",
    "behavior_lstm",
    "behavior_transformer",
    "network_anomaly",
    "network_lgbm",
    "ransomware",
    "memory_injection",
    "lolbin_detector",
    "supply_chain_detector",
    "identity_threat",
    "aigen_detector",
    "rat_c2_detector",
]

EXPECTED_DIMS = {
    "pe_classifier": (311,),
    "behavior_lstm": (50, 48),
    "behavior_transformer": (50, 48),
    "network_anomaly": (15,),
    "network_lgbm": (15,),
    "ransomware": (10,),
    "memory_injection": (32,),
    "lolbin_detector": (64,),
    "supply_chain_detector": (32,),
    "identity_threat": (24,),
    "aigen_detector": (48,),
    "rat_c2_detector": (22,),
}

MANIFEST = MODELS_DIR / "manifest.json"


def _to_dim(v, default=50):
    if isinstance(v, (int, float)):
        return int(v)
    return default


def audit():
    manifest_data = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}

    for name in MODEL_NAMES:
        onnx_path = MODELS_DIR / f"{name}.onnx"
        sig_path = MODELS_DIR / f"{name}.onnx.sig"

        if not onnx_path.exists():
            logger.warning("  %-25s MISSING", name)
            continue

        size_kb = onnx_path.stat().st_size / 1024
        has_sig = sig_path.exists()

        model = onnx.load(str(onnx_path))
        sess = ort.InferenceSession(str(onnx_path))

        inputs = []
        for inp in sess.get_inputs():
            inputs.append((inp.name, inp.shape, inp.type))

        outputs = []
        for out in sess.get_outputs():
            outputs.append((out.name, out.shape, out.type))

        inp = inputs[0]
        exp_shape = EXPECTED_DIMS.get(name, "???")

        # Build dummy with correct dims
        try:
            if len(inp[1]) == 3:
                seq_len = _to_dim(inp[1][1], 50)
                feat_dim = _to_dim(inp[1][2], 48)
                dummy = np.random.randn(3, seq_len, feat_dim).astype(np.float32)
            elif len(inp[1]) == 2:
                feat_dim = _to_dim(inp[1][1], 10)
                dummy = np.random.randn(3, feat_dim).astype(np.float32)
            else:
                dummy = np.random.randn(3, 1).astype(np.float32)

            out = sess.run(None, {inp[0]: dummy})
            scores = [np.array(o).flatten() for o in out]
            score_str = [f"{s:.4f}" for s in scores[0][:5]]
            infer_ok = True
        except Exception as e:
            score_str = [f"ERR: {str(e)[:60]}"]
            infer_ok = False

        # Check manifest
        manifest_entry = None
        for m in manifest_data.get("models", []):
            if m["name"] == name:
                manifest_entry = m
                break

        man = "manifest=✓" if manifest_entry else "manifest=✗"
        sha_ok = "sha=✓" if manifest_entry and manifest_entry.get("sha256", "") else "sha=✗"

        logger.info("")
        logger.info("  %-25s  sig=%-3s %s %s  size=%s KB",
                     name, "✓" if has_sig else "✗", man, sha_ok, f"{size_kb:.0f}")
        for inp_name, inp_shape, _ in inputs:
            logger.info("  %-25s  IN: %s (expected %s)", "", inp_shape, exp_shape)
        for out_name, out_shape, _ in outputs:
            logger.info("  %-25s  OUT: %s", "", out_name, out_shape)
        logger.info("  %-25s  %s", "", "✓" if infer_ok else "✗")
        logger.info("  %-25s  scores: %s", "", score_str)


if __name__ == "__main__":
    audit()
