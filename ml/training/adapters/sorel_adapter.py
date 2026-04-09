"""SOREL-20M dataset adapter.

Loads pre-computed features from the SOREL-20M dataset (Sophos + ReversingLabs)
and maps them to our 311-dim PE feature space.

SOREL provides EMBER-compatible 2381-dim feature vectors stored in Parquet or
JSON format, indexed by SHA256. This adapter handles streaming reads for the
full 20M-sample corpus.

Reference: "SOREL-20M: A Large Scale Benchmark Dataset for Malicious PE Detection"
           https://arxiv.org/abs/2012.07634
Dataset:   https://github.com/sophos/SOREL-20M
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.features import TOTAL_FILE_FEATURES

logger = logging.getLogger(__name__)

PE_FEATURE_DIM = TOTAL_FILE_FEATURES  # 311

SOREL_LABELS = {
    "adware": 0,
    "flooder": 1,
    "ransomware": 2,
    "dropper": 3,
    "spyware": 4,
    "packed": 5,
    "crypto_miner": 6,
    "file_infector": 7,
    "installer": 8,
    "worm": 9,
    "downloader": 10,
}


def _map_sorel_to_311(X: np.ndarray) -> np.ndarray:
    """Map SOREL's EMBER-compatible features to our 311-dim layout."""
    n, raw_dim = X.shape
    if raw_dim <= PE_FEATURE_DIM:
        if raw_dim == PE_FEATURE_DIM:
            return X.astype(np.float32)
        out = np.zeros((n, PE_FEATURE_DIM), dtype=np.float32)
        out[:, :raw_dim] = X
        return out

    out = np.zeros((n, PE_FEATURE_DIM), dtype=np.float32)
    out[:, 0:256] = X[:, 0:256]
    remaining = raw_dim - 256
    take = min(remaining, PE_FEATURE_DIM - 256)
    out[:, 256:256 + take] = X[:, 256:256 + take]
    return out


def _load_parquet(data_dir: Path, max_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """Load from SOREL Parquet files (requires pyarrow or fastparquet)."""
    import pandas as pd

    features_file = data_dir / "features.parquet"
    labels_file = data_dir / "labels.parquet"

    if not features_file.exists():
        pq_files = sorted(data_dir.glob("*.parquet"))
        if not pq_files:
            raise FileNotFoundError(f"No parquet files in {data_dir}")
        features_file = pq_files[0]

    logger.info("Reading features from %s ...", features_file)
    df_feat = pd.read_parquet(features_file)
    if max_samples > 0:
        df_feat = df_feat.head(max_samples)

    X = df_feat.select_dtypes(include=[np.number]).values.astype(np.float32)

    if labels_file.exists():
        df_labels = pd.read_parquet(labels_file)
        if max_samples > 0:
            df_labels = df_labels.head(max_samples)
        y = df_labels.iloc[:, 0].values.astype(np.int32)
    else:
        y = np.ones(len(X), dtype=np.int32)

    return X, y


def _load_jsonl(data_dir: Path, max_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """Load from SOREL JSON-lines files (one JSON object per line)."""
    jsonl_files = sorted(data_dir.glob("*.jsonl")) + sorted(data_dir.glob("*.json"))
    if not jsonl_files:
        raise FileNotFoundError(f"No JSON/JSONL files in {data_dir}")

    features_list: list[list[float]] = []
    labels_list: list[int] = []

    for jf in jsonl_files:
        logger.info("Reading %s ...", jf)
        with open(jf) as fh:
            for line in fh:
                if max_samples > 0 and len(features_list) >= max_samples:
                    break
                obj = json.loads(line.strip())
                feats = obj.get("features", obj.get("ember_features", []))
                label = obj.get("label", obj.get("is_malware", 1))
                if isinstance(label, str):
                    label = 1 if label.lower() in ("malware", "malicious") else 0
                features_list.append(feats)
                labels_list.append(int(label))
        if max_samples > 0 and len(features_list) >= max_samples:
            break

    X = np.array(features_list, dtype=np.float32)
    y = np.array(labels_list, dtype=np.int32)
    return X, y


def load(config: dict[str, Any] | None = None) -> tuple[np.ndarray, np.ndarray, dict]:
    """Load SOREL-20M and return (X, y, metadata).

    Config keys:
        data_dir (str): Path to SOREL data directory.
        format (str): "parquet" or "jsonl" (auto-detected if omitted).
        max_samples (int): Cap total samples (0 = unlimited).
        label_filter (str): Only keep samples with this tag (e.g. "ransomware").
    """
    config = config or {}
    data_dir = Path(config.get("data_dir", "./data/sorel"))
    fmt = config.get("format", "auto")
    max_samples = config.get("max_samples", 0)
    label_filter = config.get("label_filter", "")

    if fmt == "auto":
        if list(data_dir.glob("*.parquet")):
            fmt = "parquet"
        else:
            fmt = "jsonl"

    logger.info("Loading SOREL-20M (%s) from %s ...", fmt, data_dir)

    if fmt == "parquet":
        X, y = _load_parquet(data_dir, max_samples)
    else:
        X, y = _load_jsonl(data_dir, max_samples)

    X_mapped = _map_sorel_to_311(X)

    metadata = {
        "source": "sorel-20m",
        "format": fmt,
        "original_dim": X.shape[1] if X.ndim == 2 else 0,
        "mapped_dim": PE_FEATURE_DIM,
        "n_samples": len(y),
        "n_malicious": int((y == 1).sum()),
        "n_benign": int((y == 0).sum()),
    }
    logger.info(
        "SOREL-20M loaded: %d samples, mapped to %d-dim",
        metadata["n_samples"], PE_FEATURE_DIM,
    )
    return X_mapped, y, metadata
