"""Tests for dataset adapters.

These tests verify the adapter registry and individual adapter interfaces
without requiring actual datasets to be present.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestNSRLAdapter:
    def test_synthetic_benign_generation(self):
        from adapters.nsrl_adapter import load
        X, y, meta = load({"n_synthetic": 100, "rds_path": "/nonexistent"})
        assert X.shape == (100, 311)
        assert y.shape == (100,)
        assert (y == 0).all()
        assert meta["source"] == "nist_nsrl"

    def test_feature_ranges(self):
        from adapters.nsrl_adapter import load
        X, y, _ = load({"n_synthetic": 50, "rds_path": "/nonexistent"})
        byte_hist = X[:, 0:256]
        assert np.all(byte_hist >= 0)
        assert np.all(byte_hist <= 1.0 + 1e-6)


class TestEmberAdapter:
    def test_map_ember_to_311_passthrough(self):
        from adapters.ember_adapter import _map_ember_to_311
        X = np.random.randn(10, 311).astype(np.float32)
        result = _map_ember_to_311(X)
        assert result.shape == (10, 311)
        np.testing.assert_array_almost_equal(result, X)

    def test_map_ember_to_311_truncation(self):
        from adapters.ember_adapter import _map_ember_to_311
        X = np.random.randn(5, 2381).astype(np.float32)
        result = _map_ember_to_311(X)
        assert result.shape == (5, 311)
        np.testing.assert_array_almost_equal(result[:, 0:256], X[:, 0:256])

    def test_map_ember_to_311_padding(self):
        from adapters.ember_adapter import _map_ember_to_311
        X = np.ones((3, 200), dtype=np.float32)
        result = _map_ember_to_311(X)
        assert result.shape == (3, 311)
        assert np.all(result[:, 200:] == 0)


class TestSorelAdapter:
    def test_map_sorel_to_311(self):
        from adapters.sorel_adapter import _map_sorel_to_311
        X = np.random.randn(5, 2381).astype(np.float32)
        result = _map_sorel_to_311(X)
        assert result.shape == (5, 311)


class TestActivelearning:
    def test_uncertainty_evaluation(self):
        from active_learning import ActiveLearner
        al = ActiveLearner(threshold=0.5, uncertainty_band=0.15)

        queued = al.evaluate("s1", "pe", 0.52, [0.1, 0.2])
        assert queued is True

        not_queued = al.evaluate("s2", "pe", 0.95, [0.8, 0.9])
        assert not_queued is False

        assert len(al.review_queue) == 1

    def test_labeling(self):
        from active_learning import ActiveLearner
        al = ActiveLearner(threshold=0.5, uncertainty_band=0.2)
        al.evaluate("s1", "pe", 0.5, [0.1])
        al.label_sample("s1", "tp")
        assert len(al.labeled) == 1
        assert al.labeled[0].analyst_label == "tp"

    def test_priority_sampling(self):
        from active_learning import ActiveLearner
        al = ActiveLearner()
        X = np.random.randn(100, 10).astype(np.float32)
        y = np.array([0] * 90 + [1] * 10, dtype=np.int32)
        X_s, y_s = al.priority_sample(X, y, target_size=50, rare_class_weight=3.0)
        assert len(X_s) > 0
        assert len(X_s) == len(y_s)


class TestModelRegistry:
    def test_register_and_list(self, tmp_path):
        from registry import ModelRegistry

        model_file = tmp_path / "test.onnx"
        model_file.write_bytes(b"\x00" * 100)

        reg = ModelRegistry(str(tmp_path))
        entry = reg.register("test_model", "test.onnx", version="1.0.0", source="test")

        assert entry.name == "test_model"
        assert entry.version == "1.0.0"
        assert entry.status == "active"

        models = reg.list_models()
        assert len(models) == 1

    def test_promote_and_rollback(self, tmp_path):
        from registry import ModelRegistry

        for v in ("1.0.0", "2.0.0"):
            f = tmp_path / f"model_v{v}.onnx"
            f.write_bytes(b"\x00" * 100)

        reg = ModelRegistry(str(tmp_path))
        reg.register("model", "model_v1.0.0.onnx", version="1.0.0")
        reg.register("model", "model_v2.0.0.onnx", version="2.0.0")

        active = reg.get_active("model")
        assert active is not None
        assert active["version"] == "2.0.0"

        reg.rollback("model", "1.0.0")
        active = reg.get_active("model")
        assert active["version"] == "1.0.0"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
