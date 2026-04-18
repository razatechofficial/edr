"""EMBER2018 dataset adapter.

Loads the EMBER2018 open dataset and maps its features to our 311-dim PE
feature space used by the Go PEFeatureExtractor.

EMBER2018 natively produces 2381-dim feature vectors. This adapter selects
and reorders features to match our 311-dim layout:
  [byte_histogram(256) + entropy_histogram(16) + base_features(2)
   + string_features(8) + pe_features(8) + section_features(16)
   + format_features(3) + header_features(2)]

Reference: "EMBER: An Open Dataset for Training Static PE Malware ML Models"
           https://arxiv.org/abs/1804.04637
Dataset:   https://github.com/elastic/ember
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.features import TOTAL_FILE_FEATURES

logger = logging.getLogger(__name__)

PE_FEATURE_DIM = TOTAL_FILE_FEATURES  # 311

EMBER_BYTE_HISTOGRAM_OFFSET = 0
EMBER_BYTE_HISTOGRAM_SIZE = 256

EMBER_ENTRYPOINT_OFFSET = 256
EMBER_SECTION_OFFSET = 512

EMBER_RAW_DIM = 2381


def _vectorized_dat_files(data_dir: Path) -> dict[str, Path]:
    return {
        "X_train": data_dir / "X_train.dat",
        "y_train": data_dir / "y_train.dat",
        "X_test": data_dir / "X_test.dat",
        "y_test": data_dir / "y_test.dat",
    }


def _missing_vectorized_files(data_dir: Path) -> list[Path]:
    return [p for p in _vectorized_dat_files(data_dir).values() if not p.is_file()]


def _has_raw_jsonl(data_dir: Path) -> bool:
    return (data_dir / "train_features_0.jsonl").is_file() and (data_dir / "test_features.jsonl").is_file()


def _map_ember_to_311(X_ember: np.ndarray) -> np.ndarray:
    """Map EMBER's 2381-dim feature vectors to our 311-dim layout.

    When the EMBER vector is already <= 311 dims (e.g. a pre-cropped dataset),
    it is returned as-is or zero-padded.
    """
    n = X_ember.shape[0]
    raw_dim = X_ember.shape[1]

    if raw_dim <= PE_FEATURE_DIM:
        if raw_dim == PE_FEATURE_DIM:
            return X_ember.astype(np.float32)
        out = np.zeros((n, PE_FEATURE_DIM), dtype=np.float32)
        out[:, :raw_dim] = X_ember
        return out

    out = np.zeros((n, PE_FEATURE_DIM), dtype=np.float32)

    out[:, 0:256] = X_ember[:, EMBER_BYTE_HISTOGRAM_OFFSET:EMBER_BYTE_HISTOGRAM_OFFSET + 256]

    remaining = raw_dim - 256
    take = min(remaining, PE_FEATURE_DIM - 256)
    out[:, 256:256 + take] = X_ember[:, 256:256 + take]

    return out


def load(config: dict[str, Any] | None = None) -> tuple[np.ndarray, np.ndarray, dict]:
    """Load EMBER2018 and return (X, y, metadata).

    Config keys:
        data_dir (str): Path to EMBER2018 vectorized features directory.
        version  (int): Feature version, default 2.
        max_samples (int): Cap total samples (0 = unlimited).
    """
    config = config or {}
    data_dir = config.get("data_dir", "./data/ember")
    version = config.get("version", 2)
    max_samples = config.get("max_samples", 0)

    logger.info("Loading EMBER2018 from %s (feature_version=%d) ...", data_dir, version)

    # Only fall back to thrember when the *ember* package is missing.  A single
    # ``except ImportError`` around both ``import ember`` and ``read_vectorized_features``
    # incorrectly treats missing tqdm/lief (or similar) as "use thrember", which then
    # fails with ``No module named 'thrember'``.
    read_fn = None
    using_elastic_ember = False
    try:
        import ember

        read_fn = ember.read_vectorized_features
        using_elastic_ember = True
    except ImportError:
        try:
            import thrember

            read_fn = thrember.read_vectorized_features
        except ImportError as exc:
            raise ImportError(
                "Install EMBER tooling: pip install tqdm lief 'git+https://github.com/elastic/ember.git'. "
                "For EMBER2024-only layouts (no elastic ember), install: "
                "pip install 'git+https://github.com/FutureComputing4AI/EMBER2024.git'"
            ) from exc

    root = Path(data_dir)
    if using_elastic_ember:
        missing_dat = _missing_vectorized_files(root)
        if missing_dat:
            hint = ""
            if _has_raw_jsonl(root):
                hint = (
                    " Raw JSONL is present. Build vectorized features first (hours of CPU):\n"
                    "   cd ml/training && ../../.venv/bin/python vectorize_ember2018.py "
                    f'--data-dir "{root}"'
                )
            raise FileNotFoundError(
                f"EMBER vectorized files not found: {missing_dat[0].name} (and siblings). "
                "The official tarball only includes JSONL until you run ember.create_vectorized_features."
                + hint
            )

    X_train, y_train, X_test, y_test = read_fn(data_dir, feature_version=version)

    train_mask = y_train != -1
    test_mask = y_test != -1
    X_train, y_train = X_train[train_mask], y_train[train_mask]
    X_test, y_test = X_test[test_mask], y_test[test_mask]

    X = np.vstack([X_train, X_test])
    y = np.concatenate([y_train, y_test])

    if max_samples > 0 and len(X) > max_samples:
        idx = np.random.choice(len(X), max_samples, replace=False)
        X, y = X[idx], y[idx]

    X_mapped = _map_ember_to_311(X)
    y = y.astype(np.int32)

    metadata = {
        "source": "ember2018",
        "feature_version": version,
        "original_dim": X.shape[1] if X.ndim == 2 else 0,
        "mapped_dim": PE_FEATURE_DIM,
        "n_samples": len(y),
        "n_malicious": int((y == 1).sum()),
        "n_benign": int((y == 0).sum()),
    }
    logger.info(
        "EMBER2018 loaded: %d samples (%d mal / %d ben), mapped to %d-dim",
        metadata["n_samples"], metadata["n_malicious"],
        metadata["n_benign"], PE_FEATURE_DIM,
    )
    return X_mapped, y, metadata
