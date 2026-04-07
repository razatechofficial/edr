#!/usr/bin/env python3
"""Emit valid ONNX graphs for the four agent models using only numpy + onnx.

Use when PyTorch / LightGBM are unavailable (e.g. very new Python). For
production quality, prefer generate_baseline_models.py on Python 3.10–3.12.

Usage:
  pip install onnx numpy
  python generate_minimal_onnx.py --output-dir ../../models
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np

try:
    import onnx
    from onnx import TensorProto, helper, numpy_helper
except ImportError as e:  # pragma: no cover
    raise SystemExit("install onnx and numpy: pip install onnx numpy") from e

PE_DIM = 311
BEHAVIOR_SEQ = 50
BEHAVIOR_FEAT = 48
BEHAVIOR_FLAT = BEHAVIOR_SEQ * BEHAVIOR_FEAT
NET_DIM = 15
RANSOM_DIM = 10


def _save(model: onnx.ModelProto, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, str(path))
    print(f"wrote {path} ({path.stat().st_size} bytes)")


def build_pe_classifier(path: Path) -> None:
    """Input float[?,311] -> output float[?,2] (benign logit, malicious logit)."""
    w = np.random.randn(PE_DIM, 2).astype(np.float32) * 0.01
    b = np.array([0.5, -0.5], dtype=np.float32)
    graph = helper.make_graph(
        nodes=[
            helper.make_node("MatMul", ["input", "W"], ["logits"]),
            helper.make_node("Add", ["logits", "B"], ["output"]),
        ],
        name="pe_stub",
        inputs=[
            helper.make_tensor_value_info(
                "input", TensorProto.FLOAT, [None, PE_DIM]
            ),
        ],
        outputs=[
            helper.make_tensor_value_info(
                "output", TensorProto.FLOAT, [None, 2]
            ),
        ],
        initializer=[
            numpy_helper.from_array(w, name="W"),
            numpy_helper.from_array(b, name="B"),
        ],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 15)])
    onnx.checker.check_model(model)
    _save(model, path)


def build_behavior_lstm(path: Path) -> None:
    """Input float[?,50,48] -> output float[?,1] (risk score)."""
    w = np.random.randn(BEHAVIOR_FLAT, 1).astype(np.float32) * 0.001
    b = np.array([0.1], dtype=np.float32)
    graph = helper.make_graph(
        nodes=[
            helper.make_node("Flatten", ["input"], ["flat"], axis=1),
            helper.make_node("MatMul", ["flat", "W"], ["logit"]),
            helper.make_node("Add", ["logit", "B"], ["pre_sig"]),
            helper.make_node("Sigmoid", ["pre_sig"], ["score"]),
        ],
        name="behavior_stub",
        inputs=[
            helper.make_tensor_value_info(
                "input", TensorProto.FLOAT, [None, BEHAVIOR_SEQ, BEHAVIOR_FEAT]
            ),
        ],
        outputs=[
            helper.make_tensor_value_info("score", TensorProto.FLOAT, [None, 1]),
        ],
        initializer=[
            helper.make_tensor("W", TensorProto.FLOAT, list(w.shape), w.tobytes(), raw=True),
            helper.make_tensor("B", TensorProto.FLOAT, list(b.shape), b.tobytes(), raw=True),
        ],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 15)])
    onnx.checker.check_model(model)
    _save(model, path)


def build_network_anomaly(path: Path) -> None:
    """Input float[?,15] -> output float[?,1] (anomaly score)."""
    w = np.random.randn(NET_DIM, 1).astype(np.float32) * 0.02
    b = np.array([0.05], dtype=np.float32)
    graph = helper.make_graph(
        nodes=[
            helper.make_node("MatMul", ["input", "W"], ["logit"]),
            helper.make_node("Add", ["logit", "B"], ["pre_sig"]),
            helper.make_node("Sigmoid", ["pre_sig"], ["anomaly_score"]),
        ],
        name="network_stub",
        inputs=[
            helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, NET_DIM]),
        ],
        outputs=[
            helper.make_tensor_value_info(
                "anomaly_score", TensorProto.FLOAT, [None, 1]
            ),
        ],
        initializer=[
            numpy_helper.from_array(w, name="W"),
            numpy_helper.from_array(b, name="B"),
        ],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 15)])
    onnx.checker.check_model(model)
    _save(model, path)


def build_ransomware(path: Path) -> None:
    """Input float[?,10] -> output float[?,1] (risk); Go runtime reads output[0]."""
    w = np.random.randn(RANSOM_DIM, 1).astype(np.float32) * 0.05
    b = np.array([0.05], dtype=np.float32)
    graph = helper.make_graph(
        nodes=[
            helper.make_node("MatMul", ["input", "W"], ["logit"]),
            helper.make_node("Add", ["logit", "B"], ["pre_sig"]),
            helper.make_node("Sigmoid", ["pre_sig"], ["output"]),
        ],
        name="ransom_stub",
        inputs=[
            helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, RANSOM_DIM]),
        ],
        outputs=[
            helper.make_tensor_value_info("output", TensorProto.FLOAT, [None, 1]),
        ],
        initializer=[
            numpy_helper.from_array(w, name="W"),
            numpy_helper.from_array(b, name="B"),
        ],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 15)])
    onnx.checker.check_model(model)
    _save(model, path)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output-dir", default="../../models")
    args = p.parse_args()
    out = Path(args.output_dir).resolve()
    build_pe_classifier(out / "pe_classifier.onnx")
    build_behavior_lstm(out / "behavior_lstm.onnx")
    build_network_anomaly(out / "network_anomaly.onnx")
    build_ransomware(out / "ransomware.onnx")
    print("Done. Replace with generate_baseline_models.py output for trained weights.")


if __name__ == "__main__":
    main()
