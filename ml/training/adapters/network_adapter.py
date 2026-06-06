"""Network dataset adapter for CIC-IDS2017, UNSW-NB15, and CTU-13.

Maps network flow features to our 15-dim NetworkFeatureExtractor space
using the shared NetworkFeatureEncoder in utils/features.py.

Datasets:
    CIC-IDS2017:  https://www.unb.ca/cic/datasets/ids-2017.html
    CIC-IDS2018:  https://www.unb.ca/cic/datasets/ids-2018.html
    UNSW-NB15:    https://research.unsw.edu.au/projects/unsw-nb15-dataset
"""

from __future__ import annotations

import logging
import math
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.features import NETWORK_FEATURE_COUNT

logger = logging.getLogger(__name__)

NET_FEATURE_DIM = NETWORK_FEATURE_COUNT  # 15
LOG_MAX = float(math.log1p(65535))


def _port_category(port: int) -> float:
    if port <= 1023:
        return 0.0
    if port <= 49151:
        return 0.5
    return 1.0


def _to_port_int(val: Any) -> int:
    if pd.isna(val):
        return 0
    s = str(val).strip()
    if not s:
        return 0
    try:
        return int(s, 16) if s.startswith("0x") else int(float(s))
    except (ValueError, OverflowError):
        return 0


def _load_cic_ids(csv_path: Path, max_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """Vectorized CIC-IDS loading."""
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
    n = len(df)

    has_2017 = "Destination Port" in df.columns
    has_2018 = "Dst Port" in df.columns
    dest_port_col = "Destination Port" if has_2017 else ("Dst Port" if has_2018 else None)
    protocol_col = "Protocol" if "Protocol" in df.columns else None
    timestamp_col = "Timestamp" if "Timestamp" in df.columns else None

    X = np.zeros((n, NET_FEATURE_DIM), dtype=np.float32)
    log_max_f = np.float32(LOG_MAX)

    if dest_port_col:
        ports = pd.to_numeric(df[dest_port_col], errors="coerce").fillna(0).astype(np.int32).values
        X[:, 0] = np.where(ports <= 1023, 0.0, np.where(ports <= 49151, 0.5, 1.0))
        X[:, 2] = np.log1p(np.maximum(ports, 0).astype(np.float64)).astype(np.float32) / log_max_f
        X[:, 4] = (ports == 80).astype(np.float32)
        X[:, 5] = (ports == 443).astype(np.float32)
        X[:, 6] = (ports == 53).astype(np.float32)
        X[:, 7] = (ports == 22).astype(np.float32)
        X[:, 11] = ports.astype(np.float32) / 65535.0

    if protocol_col:
        protos = pd.to_numeric(df[protocol_col], errors="coerce").fillna(0).astype(np.int32).values
        X[:, 8] = (protos == 6).astype(np.float32)
        X[:, 9] = (protos == 17).astype(np.float32)

    if timestamp_col:
        ts = pd.to_datetime(df[timestamp_col], errors="coerce")
        mask = ts.notna()
        if mask.any():
            hours = ts.dt.hour.values[mask]
            minutes = ts.dt.minute.values[mask]
            seconds = ts.dt.second.values[mask]
            X[mask, 3] = (hours * 3600 + minutes * 60 + seconds).astype(np.float32) / 86400.0

    return X, y


def _load_unsw_nb15(csv_path: Path, max_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """Vectorized UNSW-NB15 loading."""
    logger.info("Loading UNSW-NB15 from %s ...", csv_path)
    df = pd.read_csv(csv_path, low_memory=False, nrows=max_samples or None)
    df.columns = df.columns.str.strip().str.lower()

    y_col = "label" if "label" in df.columns else "attack_cat"
    if y_col == "attack_cat":
        y = (df[y_col].str.strip() != "Normal").astype(np.int32).values
    else:
        y = df[y_col].astype(np.int32).values

    n = len(df)
    X = np.zeros((n, NET_FEATURE_DIM), dtype=np.float32)
    log_max_f = np.float32(LOG_MAX)

    if "dsport" in df.columns:
        ports = df["dsport"].apply(_to_port_int).values.astype(np.int32)
        X[:, 0] = np.where(ports <= 1023, 0.0, np.where(ports <= 49151, 0.5, 1.0))
        X[:, 2] = np.log1p(np.maximum(ports, 0).astype(np.float64)).astype(np.float32) / log_max_f
        X[:, 4] = (ports == 80).astype(np.float32)
        X[:, 5] = (ports == 443).astype(np.float32)
        X[:, 6] = (ports == 53).astype(np.float32)
        X[:, 7] = (ports == 22).astype(np.float32)
        X[:, 11] = ports.astype(np.float32) / 65535.0

    if "sport" in df.columns:
        src_ports = df["sport"].apply(_to_port_int).values.astype(np.int32)
        X[:, 1] = np.log1p(np.maximum(src_ports, 0).astype(np.float64)).astype(np.float32) / log_max_f
        X[:, 10] = (src_ports > 1024).astype(np.float32)

    if "proto" in df.columns:
        p = df["proto"].astype(str).str.lower().str.strip()
        X[:, 8] = p.isin(["tcp", "6"]).astype(np.float32)
        X[:, 9] = p.isin(["udp", "17"]).astype(np.float32)

    if "dstip" in df.columns:
        ips = df["dstip"].astype(str).str.strip()
        X[:, 13] = ips.apply(lambda x: _is_private_ip(x)).values.astype(np.float32)
        X[:, 14] = ips.apply(lambda x: _is_loopback(x)).values.astype(np.float32)

    if "stime" in df.columns:
        ts = pd.to_datetime(df["stime"], errors="coerce")
        mask = ts.notna()
        if mask.any():
            hours = ts.dt.hour.values[mask]
            minutes = ts.dt.minute.values[mask]
            seconds = ts.dt.second.values[mask]
            X[mask, 3] = (hours * 3600 + minutes * 60 + seconds).astype(np.float32) / 86400.0

    return X, y


def _is_private_ip(ip_str: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip_str).is_private
    except (ValueError, TypeError):
        return False


def _is_loopback(ip_str: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip_str).is_loopback
    except (ValueError, TypeError):
        return False


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

        logger.info("Loading %d CSV files from %s ...", len(csv_files), data_path)
        X_list, y_list = [], []
        per_file_limit = max_samples // len(csv_files) if max_samples > 0 else 0
        for csv_file in csv_files:
            try:
                peek = pd.read_csv(csv_file, nrows=5, low_memory=False)
                peek_cols = [c.strip().lower() for c in peek.columns]
                is_unsw = any(c in peek_cols for c in ["sbytes", "spkts", "attack_cat", "swin"])
                if is_unsw:
                    xi, yi = _load_unsw_nb15(csv_file, per_file_limit)
                else:
                    xi, yi = _load_cic_ids(csv_file, per_file_limit)
                X_list.append(xi)
                y_list.append(yi)
                logger.info("  %s: %d samples (%d attack / %d benign)",
                            csv_file.name, len(yi), int((yi == 1).sum()), int((yi == 0).sum()))
            except Exception as e:
                logger.warning("  Failed to load %s: %s", csv_file.name, e)

        if not X_list:
            raise ValueError("No CSV files could be loaded from %s", data_path)

        X = np.concatenate(X_list, axis=0)
        y = np.concatenate(y_list, axis=0)
        dataset = "multi-csv"
        source_file = str(data_path)
    else:
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

        source_file = str(data_path)

    metadata = {
        "source": dataset,
        "file": source_file,
        "mapped_dim": NET_FEATURE_DIM,
        "n_samples": len(y),
        "n_attack": int((y == 1).sum()),
        "n_benign": int((y == 0).sum()),
    }
    logger.info("%s: %d samples (%d attack / %d benign)",
                dataset, len(y), metadata["n_attack"], metadata["n_benign"])
    return X, y, metadata
