"""CTU-13 botnet dataset adapter.

Reads CTU-13 Argus binetflow files from all 13 scenarios and maps flow
features to our 15-dim Go-compatible NetworkFeatureExtractor space.

Format (Argus binetflow columns):
  StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,
  TotPkts,TotBytes,SrcBytes,Label

Botnet labels contain the word "Botnet" or specific bot names.
Background labels contain "Background".
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


def _hex_to_ip(ip_raw: str) -> str:
    if isinstance(ip_raw, str) and ip_raw.startswith("0x") and len(ip_raw) == 10:
        parts = [str(int(ip_raw[i:i+2], 16)) for i in range(2, 10, 2)]
        return ".".join(parts)
    return str(ip_raw) if isinstance(ip_raw, str) else ""


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


def _is_malicious(label: str) -> int:
    label_lower = label.lower() if isinstance(label, str) else ""
    if "background" in label_lower:
        return 0
    if "normal" in label_lower:
        return 0
    if "botnet" in label_lower:
        return 1
    if "leak" in label_lower:
        return 1
    if "c&c" in label_lower or "cnc" in label_lower or "cc" in label_lower:
        return 1
    if "attack" in label_lower:
        return 1
    if "malicious" in label_lower:
        return 1
    return 0


def _load_ctu13_scenario(scenario_dir: Path, max_samples: int) -> tuple[np.ndarray, np.ndarray]:
    binetflow_files = sorted(scenario_dir.glob("*.binetflow"))
    if not binetflow_files:
        raise FileNotFoundError(f"No binetflow files in {scenario_dir}")

    log_max_f = np.float32(LOG_MAX)
    X_list, y_list = [], []
    for bf in binetflow_files:
        logger.info("  Loading %s ...", bf.name)
        df = pd.read_csv(bf, low_memory=False, nrows=max_samples or None)
        df.columns = df.columns.str.strip()

        if "Label" not in df.columns:
            logger.warning("  No Label column in %s, skipping", bf.name)
            continue

        y = df["Label"].apply(_is_malicious).astype(np.int32).values
        n = len(df)
        X = np.zeros((n, NET_FEATURE_DIM), dtype=np.float32)

        if "Dport" in df.columns:
            ports = df["Dport"].apply(_to_port_int).values.astype(np.int32)
            X[:, 0] = np.where(ports <= 1023, 0.0, np.where(ports <= 49151, 0.5, 1.0))
            X[:, 2] = np.log1p(np.maximum(ports, 0).astype(np.float64)).astype(np.float32) / log_max_f
            X[:, 4] = (ports == 80).astype(np.float32)
            X[:, 5] = (ports == 443).astype(np.float32)
            X[:, 6] = (ports == 53).astype(np.float32)
            X[:, 7] = (ports == 22).astype(np.float32)
            X[:, 11] = ports.astype(np.float32) / 65535.0

        if "Sport" in df.columns:
            src_ports = df["Sport"].apply(_to_port_int).values.astype(np.int32)
            X[:, 1] = np.log1p(np.maximum(src_ports, 0).astype(np.float64)).astype(np.float32) / log_max_f
            X[:, 10] = (src_ports > 1024).astype(np.float32)

        if "Proto" in df.columns:
            p = df["Proto"].astype(str).str.upper().str.strip()
            X[:, 8] = (p == "TCP").astype(np.float32)
            X[:, 9] = (p == "UDP").astype(np.float32)

        if "DstAddr" in df.columns:
            ips = df["DstAddr"].astype(str).apply(_hex_to_ip)
            X[:, 13] = ips.apply(_is_private_ip).values.astype(np.float32)
            X[:, 14] = ips.apply(_is_loopback).values.astype(np.float32)

        if "StartTime" in df.columns:
            ts = pd.to_datetime(df["StartTime"], errors="coerce")
            mask = ts.notna()
            if mask.any():
                hours = ts.dt.hour.values[mask]
                minutes = ts.dt.minute.values[mask]
                seconds = ts.dt.second.values[mask]
                X[mask, 3] = (hours * 3600 + minutes * 60 + seconds).astype(np.float32) / 86400.0

        X_list.append(X)
        y_list.append(y)
        logger.info("    %s: %d samples (%d botnet / %d benign)",
                     bf.name, len(y), int((y == 1).sum()), int((y == 0).sum()))

    if not X_list:
        raise ValueError(f"No data loaded from {scenario_dir}")

    return np.concatenate(X_list, axis=0), np.concatenate(y_list, axis=0)


def load(config: dict[str, Any] | None = None) -> tuple[np.ndarray, np.ndarray, dict]:
    config = config or {}
    data_path = Path(config.get("data_path", ""))
    max_samples = config.get("max_samples", 0)
    scenarios = config.get("scenarios", None)

    if data_path.is_dir() and (data_path / "1").exists():
        scenario_dirs = sorted(
            [d for d in data_path.iterdir() if d.is_dir() and d.name.isdigit()]
        )
        if scenarios:
            scenario_dirs = [d for d in scenario_dirs if d.name in scenarios]
    elif data_path.is_dir():
        scenario_dirs = [data_path]
    else:
        raise FileNotFoundError(f"CTU-13 data path not found: {data_path}")

    logger.info("Loading CTU-13 from %d scenarios in %s ...", len(scenario_dirs), data_path)
    X_list, y_list = [], []
    per_scenario_limit = max_samples // len(scenario_dirs) if max_samples > 0 else 0

    for sd in scenario_dirs:
        try:
            xi, yi = _load_ctu13_scenario(sd, per_scenario_limit)
            X_list.append(xi)
            y_list.append(yi)
            logger.info("  Scenario %s: %d samples (%d botnet / %d benign)",
                        sd.name, len(yi), int((yi == 1).sum()), int((yi == 0).sum()))
        except Exception as e:
            logger.warning("  Scenario %s failed: %s", sd.name, e)

    if not X_list:
        raise ValueError("No CTU-13 scenarios could be loaded")

    X = np.concatenate(X_list, axis=0)
    y = np.concatenate(y_list, axis=0)

    metadata = {
        "source": "ctu-13",
        "path": str(data_path),
        "n_scenarios": len(scenario_dirs),
        "mapped_dim": NET_FEATURE_DIM,
        "n_samples": len(y),
        "n_botnet": int((y == 1).sum()),
        "n_benign": int((y == 0).sum()),
    }
    logger.info("CTU-13: %d samples (%d botnet / %d benign) across %d scenarios",
                len(y), metadata["n_botnet"], metadata["n_benign"], len(scenario_dirs))
    return X, y, metadata
