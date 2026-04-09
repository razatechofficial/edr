"""CAPE Sandbox behavioral adapter.

Parses CAPE sandbox JSON reports and converts behavioral API call sequences
into our (50, 48) event encoding matching the Go BehavioralFeatureExtractor.

CAPE generates detailed behavioral reports including API calls, network
activity, file operations, and registry changes. This adapter maps those
events into the feature encoding used by the behavior LSTM model.

Reference: https://github.com/kevoreilly/CAPEv2
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.features import (
    DEFAULT_WINDOW_SIZE,
    EVENT_SUBTYPE_INDEX,
    FEATURES_PER_EVENT,
    PROCESS_CATEGORY_INDEX,
    BehavioralFeatureEncoder,
)

logger = logging.getLogger(__name__)

SEQ_LEN = DEFAULT_WINDOW_SIZE   # 50
FEAT_DIM = FEATURES_PER_EVENT   # 48

CAPE_API_TO_EVENT = {
    "NtCreateProcess": "process_create",
    "CreateProcessInternalW": "process_create",
    "NtTerminateProcess": "process_terminate",
    "NtWriteVirtualMemory": "process_inject",
    "NtCreateFile": "file_create",
    "NtWriteFile": "file_write",
    "NtDeleteFile": "file_delete",
    "NtSetInformationFile": "file_rename",
    "NtReadFile": "file_read",
    "connect": "network_connect",
    "bind": "network_listen",
    "send": "network_send",
    "recv": "network_receive",
    "getaddrinfo": "network_dns",
    "RegCreateKeyExW": "registry_create",
    "RegSetValueExW": "registry_modify",
    "RegDeleteValueW": "registry_delete",
    "NtLoadDriver": "module_load",
    "LdrLoadDll": "module_load",
    "CryptEncrypt": "crypto_operation",
    "NtCreateUserProcess": "process_create",
    "NtOpenProcess": "process_create",
    "InternetConnectW": "network_connect",
    "HttpSendRequestW": "network_send",
    "URLDownloadToFileW": "network_receive",
    "WScript.Shell": "script_execution",
    "ShellExecuteExW": "process_create",
}


def _parse_report(report: dict) -> list[dict]:
    """Extract event sequence from a CAPE JSON report."""
    events = []
    behavior = report.get("behavior", {})

    for proc in behavior.get("processes", []):
        pid = proc.get("process_id", 0)
        proc_name = proc.get("process_name", "unknown")

        for call in proc.get("calls", []):
            api = call.get("api", "")
            event_type = CAPE_API_TO_EVENT.get(api)
            if event_type is None:
                for prefix, etype in CAPE_API_TO_EVENT.items():
                    if api.startswith(prefix):
                        event_type = etype
                        break
            if event_type is None:
                continue

            ts = call.get("time", 0)
            if isinstance(ts, str):
                try:
                    from datetime import datetime
                    ts = datetime.fromisoformat(ts).timestamp()
                except Exception:
                    ts = 0

            events.append({
                "type": event_type,
                "timestamp": ts,
                "pid": pid,
                "process_name": proc_name,
                "arguments": call.get("arguments", {}),
                "return_value": call.get("return", ""),
            })

    events.sort(key=lambda e: e.get("timestamp", 0))
    return events


def _encode_sequence(events: list[dict]) -> np.ndarray:
    """Encode a list of events into a (SEQ_LEN, FEAT_DIM) feature matrix."""
    encoder = BehavioralFeatureEncoder(window_size=SEQ_LEN)

    padded = events[:SEQ_LEN]
    while len(padded) < SEQ_LEN:
        padded.append({"type": "process_create", "timestamp": 0,
                       "pid": 0, "process_name": ""})

    matrix = np.zeros((SEQ_LEN, FEAT_DIM), dtype=np.float32)
    for i, evt in enumerate(padded):
        event_type = evt.get("type", "process_create")
        subtype_idx = EVENT_SUBTYPE_INDEX.get(event_type, 0)
        onehot_event = np.zeros(len(EVENT_SUBTYPE_INDEX), dtype=np.float32)
        if subtype_idx < len(onehot_event):
            onehot_event[subtype_idx] = 1.0

        proc_name = evt.get("process_name", "").lower()
        cat = "other"
        for cat_name in PROCESS_CATEGORY_INDEX:
            if cat_name in proc_name:
                cat = cat_name
                break
        cat_idx = PROCESS_CATEGORY_INDEX.get(cat, 0)
        onehot_cat = np.zeros(len(PROCESS_CATEGORY_INDEX), dtype=np.float32)
        if cat_idx < len(onehot_cat):
            onehot_cat[cat_idx] = 1.0

        priv_level = np.zeros(3, dtype=np.float32)
        priv_level[0] = 1.0  # default: standard

        time_feats = np.zeros(12, dtype=np.float32)
        ts = evt.get("timestamp", 0)
        if isinstance(ts, (int, float)) and ts > 0:
            from datetime import datetime
            dt = datetime.fromtimestamp(ts)
            hour = dt.hour
            time_feats[hour // 2] = 1.0

        total_used = len(onehot_event) + len(onehot_cat) + len(priv_level) + len(time_feats)
        row = np.concatenate([onehot_event, onehot_cat, priv_level, time_feats])
        matrix[i, :min(len(row), FEAT_DIM)] = row[:FEAT_DIM]

    return matrix


def load(config: dict[str, Any] | None = None) -> tuple[np.ndarray, np.ndarray, dict]:
    """Load CAPE reports and return (X, y, metadata).

    Config keys:
        reports_dir (str): Directory containing CAPE JSON report files.
        max_samples (int): Cap total samples (0 = unlimited).
        label_key (str): JSON key for label (default: "malscore").
        malicious_threshold (float): Malscore above which sample is malicious.
    """
    config = config or {}
    reports_dir = Path(config.get("reports_dir", "./data/cape"))
    max_samples = config.get("max_samples", 0)
    label_key = config.get("label_key", "malscore")
    threshold = config.get("malicious_threshold", 5.0)

    report_files = sorted(reports_dir.glob("*.json"))
    if max_samples > 0:
        report_files = report_files[:max_samples]

    logger.info("Loading %d CAPE reports from %s ...", len(report_files), reports_dir)

    X_list: list[np.ndarray] = []
    y_list: list[int] = []

    for rf in report_files:
        try:
            report = json.loads(rf.read_text())
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", rf, exc)
            continue

        events = _parse_report(report)
        if not events:
            continue

        matrix = _encode_sequence(events)
        X_list.append(matrix.flatten())

        info = report.get("info", {})
        score = info.get(label_key, info.get("score", 0))
        if isinstance(score, str):
            try:
                score = float(score)
            except ValueError:
                score = 0
        y_list.append(1 if score >= threshold else 0)

    if not X_list:
        flat_dim = SEQ_LEN * FEAT_DIM
        X = np.zeros((0, flat_dim), dtype=np.float32)
        y = np.zeros(0, dtype=np.int32)
    else:
        X = np.stack(X_list)
        y = np.array(y_list, dtype=np.int32)

    metadata = {
        "source": "cape_sandbox",
        "n_samples": len(y),
        "n_malicious": int((y == 1).sum()),
        "n_benign": int((y == 0).sum()),
        "seq_len": SEQ_LEN,
        "feat_dim": FEAT_DIM,
    }
    logger.info("CAPE: %d samples (%d mal / %d ben)", len(y),
                metadata["n_malicious"], metadata["n_benign"])
    return X, y, metadata
