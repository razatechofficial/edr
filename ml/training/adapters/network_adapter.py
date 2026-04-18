"""Network dataset adapter for CIC-IDS2017, UNSW-NB15, and CTU-13.

Maps network flow features from standard intrusion detection datasets to our
15-dim NetworkFeatureExtractor space used by the Go agent.

Datasets:
    CIC-IDS2017:  https://www.unb.ca/cic/datasets/ids-2017.html
    UNSW-NB15:    https://research.unsw.edu.au/projects/unsw-nb15-dataset
    CTU-13:       https://www.stratosphereips.org/datasets-ctu13
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.features import NETWORK_FEATURE_COUNT

logger = logging.getLogger(__name__)

NET_FEATURE_DIM = NETWORK_FEATURE_COUNT  # 15

CIC_FEATURE_MAP = {
    "Destination Port": "dst_port_cat",
    "Flow Duration": "duration",
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "Flow Bytes/s": "bytes_per_sec",
    "Flow Packets/s": "packets_per_sec",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Bwd IAT Mean": "bwd_iat_mean",
    "SYN Flag Count": "syn_count",
    "RST Flag Count": "rst_count",
    "PSH Flag Count": "psh_count",
    "ACK Flag Count": "ack_count",
}

UNSW_FEATURE_MAP = {
    "dur": "duration",
    "sbytes": "fwd_bytes",
    "dbytes": "bwd_bytes",
    "spkts": "fwd_packets",
    "dpkts": "bwd_packets",
    "sttl": "src_ttl",
    "dttl": "dst_ttl",
    "sload": "src_load",
    "dload": "dst_load",
    "dsport": "dst_port_cat",
}


def _port_category(port: float) -> float:
    """Encode destination port as a category score in [0, 1]."""
    p = int(port) if not np.isnan(port) else 0
    if p in (80, 443, 8080, 8443):
        return 0.1
    if p in (22, 23, 3389):
        return 0.6
    if p in (53,):
        return 0.2
    if p in (445, 135, 139):
        return 0.7
    if p < 1024:
        return 0.3
    if p > 49152:
        return 0.5
    return 0.4


def _normalize_column(series: pd.Series) -> np.ndarray:
    """Min-max normalize a pandas series to [0, 1]."""
    s = pd.to_numeric(series, errors="coerce").fillna(0)
    mn, mx = s.min(), s.max()
    if mx - mn < 1e-10:
        return np.zeros(len(s), dtype=np.float32)
    return ((s - mn) / (mx - mn)).values.astype(np.float32)


def _load_cic_ids(csv_path: Path, max_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """Load CIC-IDS2017/2018 CSV and map to 15-dim."""
    logger.info("Loading CIC-IDS from %s ...", csv_path)
    df = pd.read_csv(csv_path, low_memory=False, nrows=max_samples or None)
    df.columns = df.columns.str.strip()

    label_col = None
    for candidate in ("Label", "label", " Label"):
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise ValueError(f"No label column found in {csv_path}")

    y = (df[label_col].str.strip().str.upper() != "BENIGN").astype(np.int32).values

    X = np.zeros((len(df), NET_FEATURE_DIM), dtype=np.float32)
    idx = 0
    for cic_col, _ in CIC_FEATURE_MAP.items():
        if cic_col in df.columns and idx < NET_FEATURE_DIM:
            if cic_col == "Destination Port":
                X[:, idx] = df[cic_col].apply(_port_category).values.astype(np.float32)
            else:
                X[:, idx] = _normalize_column(df[cic_col])
            idx += 1

    return X, y


def _load_unsw_nb15(csv_path: Path, max_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """Load UNSW-NB15 CSV and map to 15-dim."""
    logger.info("Loading UNSW-NB15 from %s ...", csv_path)
    df = pd.read_csv(csv_path, low_memory=False, nrows=max_samples or None)
    df.columns = df.columns.str.strip().str.lower()

    y_col = "label" if "label" in df.columns else "attack_cat"
    if y_col == "attack_cat":
        y = (df[y_col].str.strip() != "Normal").astype(np.int32).values
    else:
        y = df[y_col].astype(np.int32).values

    X = np.zeros((len(df), NET_FEATURE_DIM), dtype=np.float32)
    idx = 0
    for unsw_col, _ in UNSW_FEATURE_MAP.items():
        if unsw_col in df.columns and idx < NET_FEATURE_DIM:
            if unsw_col == "dsport":
                X[:, idx] = pd.to_numeric(df[unsw_col], errors="coerce").fillna(0).apply(_port_category).values.astype(np.float32)
            else:
                X[:, idx] = _normalize_column(df[unsw_col])
            idx += 1

    return X, y


def load(config: dict[str, Any] | None = None) -> tuple[np.ndarray, np.ndarray, dict]:
    """Load network dataset and return (X, y, metadata).

    Config keys:
        dataset (str): "cic-ids2017", "unsw-nb15", or "auto" (default).
        data_path (str): Path to CSV file or directory.
        max_samples (int): Cap total samples (0 = unlimited).
    """
    config = config or {}
    dataset = config.get("dataset", "auto")
    data_path = Path(config.get("data_path", "./data/network"))
    max_samples = config.get("max_samples", 0)

    if data_path.is_dir():
        csv_files = sorted(data_path.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files in {data_path}")
        data_path = csv_files[0]

    if dataset == "auto":
        path_hint = str(data_path.resolve()).lower()
        name = data_path.stem.lower()
        if "unsw" in path_hint or "nb15" in path_hint or "unsw" in name or "nb15" in name:
            dataset = "unsw-nb15"
        else:
            dataset = "cic-ids2017"

    if dataset == "unsw-nb15":
        X, y = _load_unsw_nb15(data_path, max_samples)
    else:
        X, y = _load_cic_ids(data_path, max_samples)

    metadata = {
        "source": dataset,
        "file": str(data_path),
        "mapped_dim": NET_FEATURE_DIM,
        "n_samples": len(y),
        "n_attack": int((y == 1).sum()),
        "n_benign": int((y == 0).sum()),
    }
    logger.info("%s: %d samples (%d attack / %d benign)",
                dataset, len(y), metadata["n_attack"], metadata["n_benign"])
    return X, y, metadata
