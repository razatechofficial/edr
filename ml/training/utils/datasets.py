"""Dataset loading and synthetic data generation.

Provides loaders for real datasets (EMBER, CIC-IDS2017) and generators for
synthetic training data so pipelines can run end-to-end without downloads.
"""

from __future__ import annotations

import logging
import math
import random
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from sklearn.model_selection import train_test_split

from utils.features import (
    BYTE_HISTOGRAM_SIZE,
    DEFAULT_WINDOW_SIZE,
    ENTROPY_BINS,
    EVENT_SUBTYPE_INDEX,
    FEATURES_PER_EVENT,
    NETWORK_FEATURE_COUNT,
    PROCESS_CATEGORY_INDEX,
    RANSOMWARE_FEATURE_COUNT,
    RANSOMWARE_FEATURE_KEYS,
    TOTAL_FILE_FEATURES,
    BehavioralFeatureEncoder,
    NetworkFeatureEncoder,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# EMBER dataset
# ---------------------------------------------------------------------------


def load_ember_dataset(data_dir: str) -> tuple[np.ndarray, np.ndarray]:
    """Load EMBER2018 vectorized features (``ember``) or EMBER2024-style data (``thrember``).

    Delegates to ``adapters.ember_adapter.load``, which picks ``ember`` or ``thrember``
    only for *import* failures.  Dataset read errors (missing ``X_train.dat``, etc.)
    propagate with a clear message.

    Returns ``(X, y)`` where X is mapped to ``(n, 311)`` and y is ``{0, 1}``.
    Unlabeled samples are dropped.
    """
    from adapters.ember_adapter import load as load_ember

    X, y, _ = load_ember({"data_dir": data_dir, "version": 2})
    return X, y


# ---------------------------------------------------------------------------
# Synthetic PE data
# ---------------------------------------------------------------------------


def generate_synthetic_pe_data(
    n_benign: int = 5000,
    n_malicious: int = 5000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic 311-dim PE feature vectors.

    Benign files mimic normal byte distributions, low string/IP counts, and
    valid PE signatures.  Malicious files show high entropy, packed sections,
    suspicious string patterns, and missing signatures.
    """
    rng = np.random.RandomState(seed)
    n = n_benign + n_malicious
    X = np.zeros((n, TOTAL_FILE_FEATURES), dtype=np.float32)
    y = np.zeros(n, dtype=np.int32)

    for i in range(n):
        is_mal = i >= n_benign
        idx = 0

        # Byte histogram: malware tends toward uniform; benign toward sparse.
        if is_mal:
            hist = rng.dirichlet(np.ones(BYTE_HISTOGRAM_SIZE) * 1.0)
        else:
            alpha = np.ones(BYTE_HISTOGRAM_SIZE) * 0.01
            for peak in rng.choice(BYTE_HISTOGRAM_SIZE, size=10, replace=False):
                alpha[peak] = 5.0
            hist = rng.dirichlet(alpha)
        X[i, idx : idx + BYTE_HISTOGRAM_SIZE] = hist.astype(np.float32)
        idx += BYTE_HISTOGRAM_SIZE

        # Entropy histogram.
        ent_hist = rng.dirichlet(np.ones(ENTROPY_BINS))
        if is_mal:
            ent_hist[-1] += 0.3  # shift toward high entropy
            ent_hist /= ent_hist.sum()
        X[i, idx : idx + ENTROPY_BINS] = ent_hist.astype(np.float32)
        idx += ENTROPY_BINS

        # Whole-file entropy.
        X[i, idx] = rng.uniform(7.0, 7.99) if is_mal else rng.uniform(3.0, 6.5)
        idx += 1
        # Log file size.
        X[i, idx] = rng.uniform(8, 18) if is_mal else rng.uniform(10, 16)
        idx += 1

        # String stats.
        if is_mal:
            X[i, idx + 0] = np.float32(math.log1p(rng.randint(0, 20)))  # urls
            X[i, idx + 1] = np.float32(math.log1p(rng.randint(0, 15)))  # ips
            X[i, idx + 2] = np.float32(math.log1p(rng.randint(0, 30)))  # registry
            X[i, idx + 3] = np.float32(math.log1p(rng.randint(5, 50)))  # paths
            X[i, idx + 4] = np.float32(math.log1p(rng.randint(0, 10)))  # base64
            X[i, idx + 5] = np.float32(math.log1p(rng.randint(20, 300)))
            X[i, idx + 6] = rng.uniform(8, 30)
            X[i, idx + 7] = rng.uniform(0.3, 1.0)
        else:
            X[i, idx + 0] = np.float32(math.log1p(rng.randint(0, 5)))
            X[i, idx + 1] = np.float32(math.log1p(rng.randint(0, 3)))
            X[i, idx + 2] = np.float32(math.log1p(rng.randint(0, 5)))
            X[i, idx + 3] = np.float32(math.log1p(rng.randint(0, 20)))
            X[i, idx + 4] = np.float32(math.log1p(rng.randint(0, 3)))
            X[i, idx + 5] = np.float32(math.log1p(rng.randint(5, 100)))
            X[i, idx + 6] = rng.uniform(4, 15)
            X[i, idx + 7] = rng.uniform(0.0, 0.5)
        idx += 8

        # PE features (8).
        if is_mal:
            X[i, idx + 0] = rng.choice([1, 2, 3, 4, 8])  # sections
            X[i, idx + 1] = np.float32(math.log1p(rng.randint(0, 20)))  # imports
            X[i, idx + 2] = rng.choice([0, 1])  # exports
            X[i, idx + 3] = 0.0  # no signature
            X[i, idx + 4] = rng.choice([0.0, 1.0], p=[0.7, 0.3])
            X[i, idx + 5] = rng.uniform(0, 2)  # compile age
            X[i, idx + 6] = rng.uniform(0.7, 1.0)  # avg section entropy
            X[i, idx + 7] = rng.uniform(0.6, 1.0)
        else:
            X[i, idx + 0] = rng.choice([3, 4, 5, 6, 7])
            X[i, idx + 1] = np.float32(math.log1p(rng.randint(5, 200)))
            X[i, idx + 2] = rng.choice([0, 1])
            X[i, idx + 3] = rng.choice([0.0, 1.0], p=[0.3, 0.7])
            X[i, idx + 4] = rng.choice([0.0, 1.0], p=[0.4, 0.6])
            X[i, idx + 5] = rng.uniform(0, 4)
            X[i, idx + 6] = rng.uniform(0.3, 0.7)
            X[i, idx + 7] = rng.uniform(0.2, 0.6)
        idx += 8

        # Section entropies (16).
        n_sec = int(X[i, idx - 8])
        for s in range(min(n_sec, 16)):
            X[i, idx + s] = rng.uniform(0.8, 1.0) if is_mal else rng.uniform(0.2, 0.7)
        idx += 16

        # Format flags.
        X[i, idx] = 1.0  # PE
        idx += 3

        # Header features.
        X[i, idx] = rng.uniform(10, 20)
        X[i, idx + 1] = rng.uniform(1.0, 3.0) if is_mal else rng.uniform(0.8, 1.5)

        y[i] = 1 if is_mal else 0

    return X, y


# ---------------------------------------------------------------------------
# Synthetic Behavioral data
# ---------------------------------------------------------------------------

_BENIGN_PATTERNS: list[list[dict[str, Any]]] = [
    # Office workflow.
    [
        {"subtype": "process_create", "category": "office", "privilege": "medium"},
        {"subtype": "file_read", "category": "unknown", "privilege": "low"},
        {"subtype": "file_write", "category": "unknown", "privilege": "low", "file_write_flag": 1},
        {"subtype": "network_connect", "category": "unknown", "privilege": "low", "network_flag": 1},
        {"subtype": "file_write", "category": "unknown", "privilege": "low", "file_write_flag": 1},
    ],
    # Shell scripting.
    [
        {"subtype": "process_create", "category": "shell", "privilege": "medium"},
        {"subtype": "file_read", "category": "unknown", "privilege": "low"},
        {"subtype": "process_create", "category": "scripting", "privilege": "medium"},
        {"subtype": "file_write", "category": "unknown", "privilege": "low", "file_write_flag": 1},
        {"subtype": "process_terminate", "category": "scripting", "privilege": "medium"},
    ],
    # Browsing.
    [
        {"subtype": "process_create", "category": "browser", "privilege": "low"},
        {"subtype": "network_connect", "category": "unknown", "privilege": "low", "network_flag": 1},
        {"subtype": "network_dns", "category": "unknown", "privilege": "low", "network_flag": 1},
        {"subtype": "file_write", "category": "unknown", "privilege": "low", "file_write_flag": 1},
        {"subtype": "network_connect", "category": "unknown", "privilege": "low", "network_flag": 1},
    ],
    # Compilation.
    [
        {"subtype": "process_create", "category": "compiler", "privilege": "medium"},
        {"subtype": "file_read", "category": "unknown", "privilege": "low"},
        {"subtype": "file_create", "category": "unknown", "privilege": "low", "file_write_flag": 1},
        {"subtype": "process_terminate", "category": "compiler", "privilege": "medium"},
        {"subtype": "process_create", "category": "shell", "privilege": "medium"},
    ],
]

_MALICIOUS_PATTERNS: list[list[dict[str, Any]]] = [
    # Credential theft chain.
    [
        {"subtype": "process_create", "category": "shell", "privilege": "high"},
        {"subtype": "memory_alloc", "category": "unknown", "privilege": "high"},
        {"subtype": "memory_protect", "category": "unknown", "privilege": "high"},
        {"subtype": "ptrace_attach", "category": "debugger", "privilege": "high"},
        {"subtype": "auth_login", "category": "system", "privilege": "high"},
        {"subtype": "file_read", "category": "unknown", "privilege": "high"},
        {"subtype": "network_connect", "category": "unknown", "privilege": "high", "network_flag": 1},
    ],
    # Ransomware behavior.
    [
        {"subtype": "process_create", "category": "unknown", "privilege": "high"},
        {"subtype": "file_read", "category": "unknown", "privilege": "high"},
        {"subtype": "file_write", "category": "unknown", "privilege": "high", "file_write_flag": 1},
        {"subtype": "file_rename", "category": "unknown", "privilege": "high"},
        {"subtype": "file_delete", "category": "unknown", "privilege": "high"},
        {"subtype": "registry_write", "category": "unknown", "privilege": "high", "registry_flag": 1},
        {"subtype": "network_connect", "category": "unknown", "privilege": "high", "network_flag": 1},
    ],
    # RAT / C2 beacon.
    [
        {"subtype": "process_create", "category": "shell", "privilege": "high"},
        {"subtype": "network_connect", "category": "unknown", "privilege": "high", "network_flag": 1},
        {"subtype": "network_send", "category": "unknown", "privilege": "high", "network_flag": 1},
        {"subtype": "network_receive", "category": "unknown", "privilege": "high", "network_flag": 1},
        {"subtype": "process_inject", "category": "unknown", "privilege": "high"},
        {"subtype": "registry_write", "category": "unknown", "privilege": "high", "registry_flag": 1},
        {"subtype": "file_write", "category": "unknown", "privilege": "high", "file_write_flag": 1},
    ],
    # Privilege escalation + lateral movement.
    [
        {"subtype": "process_create", "category": "unknown", "privilege": "low"},
        {"subtype": "auth_privilege", "category": "system", "privilege": "high"},
        {"subtype": "process_create", "category": "shell", "privilege": "high"},
        {"subtype": "registry_create", "category": "unknown", "privilege": "high", "registry_flag": 1},
        {"subtype": "network_connect", "category": "unknown", "privilege": "high", "network_flag": 1},
        {"subtype": "module_load", "category": "unknown", "privilege": "high"},
        {"subtype": "process_inject", "category": "unknown", "privilege": "high"},
    ],
]


def _expand_pattern(
    pattern: list[dict[str, Any]],
    window_size: int,
    rng: random.Random,
) -> list[dict[str, Any]]:
    """Repeat/shuffle a short pattern to fill *window_size* events and add
    timestamps + parent scores."""
    events: list[dict[str, Any]] = []
    base_time = datetime(2025, 1, 15, rng.randint(0, 23), rng.randint(0, 59))
    while len(events) < window_size:
        for ev_template in pattern:
            if len(events) >= window_size:
                break
            ev = dict(ev_template)
            ev.setdefault("network_flag", 0)
            ev.setdefault("file_write_flag", 0)
            ev.setdefault("registry_flag", 0)
            ev["timestamp"] = base_time + timedelta(seconds=len(events) * rng.uniform(0.1, 5.0))
            ev["parent_score"] = rng.choice([0.0, 0.5, 1.0])
            events.append(ev)
    return events[:window_size]


def generate_synthetic_behavior_data(
    n_benign: int = 3000,
    n_malicious: int = 3000,
    window_size: int = DEFAULT_WINDOW_SIZE,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate labeled behavioral sequences as ``(n, window_size, 48)`` arrays."""
    rng = random.Random(seed)
    encoder = BehavioralFeatureEncoder(window_size)
    n = n_benign + n_malicious
    X = np.zeros((n, window_size, FEATURES_PER_EVENT), dtype=np.float32)
    y = np.zeros(n, dtype=np.int32)

    for i in range(n_benign):
        pattern = rng.choice(_BENIGN_PATTERNS)
        events = _expand_pattern(pattern, window_size, rng)
        X[i] = encoder.encode(events)
        y[i] = 0

    for i in range(n_malicious):
        pattern = rng.choice(_MALICIOUS_PATTERNS)
        events = _expand_pattern(pattern, window_size, rng)
        X[n_benign + i] = encoder.encode(events)
        y[n_benign + i] = 1

    return X, y


# ---------------------------------------------------------------------------
# Synthetic Network data
# ---------------------------------------------------------------------------


def generate_synthetic_network_data(
    n_normal: int = 5000,
    n_anomalous: int = 2000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic 15-dim network connection features."""
    rng = np.random.RandomState(seed)
    encoder = NetworkFeatureEncoder()
    n = n_normal + n_anomalous
    X = np.zeros((n, NETWORK_FEATURE_COUNT), dtype=np.float32)
    y = np.zeros(n, dtype=np.int32)

    normal_ports = [80, 443, 53, 22, 8080, 8443, 3306, 5432]
    anomalous_ports = [4444, 5555, 6666, 31337, 12345, 9999, 1337, 8888]

    for i in range(n):
        is_anom = i >= n_normal
        if is_anom:
            conn = {
                "dest_port": int(rng.choice(anomalous_ports + [rng.randint(1025, 65535)])),
                "src_port": int(rng.randint(1025, 65535)),
                "protocol": rng.choice(["tcp", "udp"]),
                "domain": "" if rng.random() > 0.3 else f"{rng.randint(0,255)}.{rng.randint(0,255)}.example.com",
                "dest_ip": f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
                "timestamp": rng.uniform(0.0, 1.0),
            }
        else:
            conn = {
                "dest_port": int(rng.choice(normal_ports)),
                "src_port": int(rng.randint(1025, 65535)),
                "protocol": "tcp" if rng.random() > 0.2 else "udp",
                "domain": f"service-{rng.randint(0,100)}.internal.corp",
                "dest_ip": f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
                "timestamp": rng.uniform(0.25, 0.75),  # business hours
            }
        X[i] = encoder.encode(conn)
        y[i] = 1 if is_anom else 0

    return X, y


# ---------------------------------------------------------------------------
# Synthetic Ransomware data
# ---------------------------------------------------------------------------


def generate_synthetic_ransomware_data(
    n_benign: int = 5000,
    n_ransomware: int = 3000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic 10-dim ransomware indicator vectors."""
    rng = np.random.RandomState(seed)
    n = n_benign + n_ransomware
    X = np.zeros((n, RANSOMWARE_FEATURE_COUNT), dtype=np.float32)
    y = np.zeros(n, dtype=np.int32)

    for i in range(n):
        is_ransom = i >= n_benign
        if is_ransom:
            X[i, 0] = rng.uniform(0.5, 1.0)   # entropy_increase_rate
            X[i, 1] = rng.uniform(0.3, 1.0)   # file_rename_rate
            X[i, 2] = rng.uniform(0.2, 0.8)   # file_delete_rate
            X[i, 3] = rng.uniform(0.4, 1.0)   # file_type_change_rate
            X[i, 4] = rng.uniform(0.5, 1.0)   # known_extension_append
            X[i, 5] = rng.uniform(0.3, 1.0)   # ransom_note_similarity
            X[i, 6] = rng.choice([0.0, 1.0], p=[0.3, 0.7])  # shadow_copy_deletion
            X[i, 7] = rng.uniform(0.3, 1.0)   # encryption_api_calls
            X[i, 8] = rng.uniform(0.2, 0.9)   # network_beacon_rate
            X[i, 9] = rng.uniform(0.3, 1.0)   # unique_file_extensions
        else:
            X[i, 0] = rng.uniform(0.0, 0.3)
            X[i, 1] = rng.uniform(0.0, 0.2)
            X[i, 2] = rng.uniform(0.0, 0.15)
            X[i, 3] = rng.uniform(0.0, 0.2)
            X[i, 4] = rng.uniform(0.0, 0.1)
            X[i, 5] = rng.uniform(0.0, 0.1)
            X[i, 6] = 0.0
            X[i, 7] = rng.uniform(0.0, 0.15)
            X[i, 8] = rng.uniform(0.0, 0.15)
            X[i, 9] = rng.uniform(0.0, 0.2)

        y[i] = 1 if is_ransom else 0

    return X, y


# ---------------------------------------------------------------------------
# General utilities
# ---------------------------------------------------------------------------


def split_dataset(
    X: np.ndarray,
    y: np.ndarray,
    test_size: float = 0.2,
    val_size: float = 0.1,
    seed: int = 42,
) -> dict[str, np.ndarray]:
    """Split into train / val / test sets, stratified by y."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y,
    )
    relative_val = val_size / (1 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=relative_val, random_state=seed, stratify=y_train,
    )
    return {
        "X_train": X_train,
        "y_train": y_train,
        "X_val": X_val,
        "y_val": y_val,
        "X_test": X_test,
        "y_test": y_test,
    }
