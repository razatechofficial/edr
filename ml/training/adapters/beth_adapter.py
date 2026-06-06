"""BETH dataset adapter for behavioral anomaly model training.

Converts BETH system call trace data into the (50, 48) event sequence format
expected by BehaviorLSTM and BehaviorTransformer.

Dataset: https://data.hpc.imperial.ac.uk/resolve/?doi=9422
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

WINDOW_SIZE = 50
FEATURES_PER_EVENT = 48

# Map BETH event names to behavioral event subtypes
EVENT_SUBTYPE_MAP = {
    # File operations
    "open": "file_open",
    "openat": "file_open",
    "read": "file_read",
    "write": "file_write",
    "readv": "file_read",
    "writev": "file_write",
    "pread64": "file_read",
    "pwrite64": "file_write",
    "sendfile": "file_read",
    "close": "file_close",
    "newfstatat": "file_open",
    "statfs": "file_open",
    "fstat": "file_open",
    "lseek": "file_read",
    "truncate": "file_write",
    "ftruncate": "file_write",
    "fallocate": "file_write",
    "copy_file_range": "file_write",
    # Process operations
    "clone": "process_create",
    "fork": "process_create",
    "vfork": "process_create",
    "execve": "process_create",
    "execveat": "process_create",
    "exit": "process_exit",
    "exit_group": "process_exit",
    "kill": "process_create",
    "tkill": "process_create",
    "ptrace": "process_inject",
    # Network operations
    "socket": "network_connect",
    "connect": "network_connect",
    "bind": "network_listen",
    "listen": "network_listen",
    "accept": "network_accept",
    "sendto": "network_send",
    "recvfrom": "network_recv",
    "sendmsg": "network_send",
    "recvmsg": "network_recv",
    "sendmmsg": "network_send",
    "recvmmsg": "network_recv",
    # Memory operations
    "mmap": "memory_alloc",
    "munmap": "memory_free",
    "mprotect": "memory_protect",
    "brk": "memory_alloc",
    "mremap": "memory_alloc",
    "shmget": "memory_alloc",
    "shmat": "memory_alloc",
    "shmdt": "memory_free",
    # Registry-like operations (config/sysfs)
    "prctl": "registry_write",
    "setxattr": "registry_write",
    "getxattr": "registry_read",
    "syslog": "registry_read",
    "sysinfo": "registry_read",
    # Privilege operations
    "setuid": "privilege_escalation",
    "setgid": "privilege_escalation",
    "setresuid": "privilege_escalation",
    "setresgid": "privilege_escalation",
    "capset": "privilege_escalation",
}

# Map common BETH process names to process categories
PROCESS_CATEGORY_MAP: dict[str, str] = {
    "sshd": "remote_access",
    "ssh": "remote_access",
    "sshd": "remote_access",
    "bash": "shell",
    "dash": "shell",
    "sh": "shell",
    "zsh": "shell",
    "python": "script_interpreter",
    "python3": "script_interpreter",
    "perl": "script_interpreter",
    "node": "script_interpreter",
    "ruby": "script_interpreter",
    "php": "script_interpreter",
    "wget": "downloader",
    "curl": "downloader",
    "nc": "network_tool",
    "netcat": "network_tool",
    "nmap": "network_tool",
    "ping": "network_tool",
    "tcpdump": "network_tool",
    "systemd": "system",
    "systemd-journal": "system",
    "cron": "system",
    "apache2": "web_server",
    "nginx": "web_server",
    "mysqld": "database",
    "postgres": "database",
    "rsync": "file_sync",
    "scp": "file_sync",
    "ls": "file_operation",
    "cp": "file_operation",
    "mv": "file_operation",
    "rm": "file_operation",
    "cat": "file_operation",
    "chmod": "file_operation",
    "chown": "file_operation",
    "touch": "file_operation",
    "mkdir": "file_operation",
    "sudo": "privileged",
    "su": "privileged",
    "pkexec": "privileged",
    "docker": "container",
    "docker-containe": "container",
    "containerd": "container",
    "runc": "container",
}


def load_beth_dataset(
    csv_path: str | Path,
    max_sequences: int = 0,
    include_per_host: bool = True,
) -> tuple[np.ndarray, np.ndarray]:
    """Load BETH dataset and convert to (N, WINDOW_SIZE, FEATURES_PER_EVENT).

    Loads the labelled_training_data.csv + per-host CSVs for attack data.

    Args:
        csv_path: Path to BETH directory or CSV file.
        max_sequences: Max number of sequences to return (0 = unlimited).
        include_per_host: Also load per-host CSVs with attack data.

    Returns:
        X: (N, 50, 48) event sequences
        y: (N,) binary labels (0=benign, 1=malicious)
    """
    beth_path = Path(csv_path)
    all_dfs = []

    if beth_path.is_dir():
        # Load aggregated splits
        for split in ["labelled_training_data.csv", "labelled_testing_data.csv", "labelled_validation_data.csv"]:
            f = beth_path / split
            if f.exists():
                df = pd.read_csv(f, low_memory=False)
                if "evil" in df.columns:
                    all_dfs.append(df)

        # Load per-host CSVs (contain real attack data)
        if include_per_host:
            for f in sorted(beth_path.glob("labelled_2021may-*.csv")):
                if "-dns" in f.name:
                    continue
                df = pd.read_csv(f, low_memory=False)
                if "evil" in df.columns and df["evil"].nunique() > 1:
                    all_dfs.append(df)
    else:
        df = pd.read_csv(beth_path, low_memory=False)
        all_dfs.append(df)

    if not all_dfs:
        raise ValueError(f"No valid BETH CSV files found at {beth_path}")

    df = pd.concat(all_dfs, ignore_index=True)
    logger.info("Combined %d events from %d sources", len(df), len(all_dfs))

    # Required columns
    required = ["eventName", "processName", "evil"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    # Use 'evil' as label (0=benign, 1=malicious)
    df["label"] = pd.to_numeric(df["evil"], errors="coerce").fillna(-1).astype(np.int32)
    df = df[df["label"] >= 0]

    logger.info("Total labeled events: %d (%d malicious)",
                 len(df), int((df["label"] == 1).sum()))

    # Fill missing columns
    if "hostName" not in df.columns:
        df["hostName"] = "default"
    if "timestamp" not in df.columns:
        df["timestamp"] = range(len(df))

    # Sort within each host+process by timestamp
    df_sorted = df.sort_values(by=["hostName", "processId", "timestamp"])

    sequences = []
    labels = []

    groups = df_sorted.groupby(["hostName", "processId"])
    for _name, group in groups:
        events = group.to_dict("records")
        label = int(group["label"].max())

        # Slide window with 50% overlap
        for i in range(0, len(events), WINDOW_SIZE // 2):
            window = events[i:i + WINDOW_SIZE]
            if len(window) < WINDOW_SIZE // 2:
                continue

            encoded = _encode_sequence(window)
            if encoded is not None:
                sequences.append(encoded)
                labels.append(label)

            if max_sequences > 0 and len(sequences) >= max_sequences:
                break
        if max_sequences > 0 and len(sequences) >= max_sequences:
            break

    X = np.array(sequences, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    # Shuffle
    rng = np.random.RandomState(42)
    idx = rng.permutation(len(y))
    X = X[idx]
    y = y[idx]

    logger.info("Extracted %d sequences (%d malicious / %d benign)",
                len(y), int(y.sum()), int((y == 0).sum()))
    return X, y


def _encode_sequence(events: list[dict]) -> np.ndarray | None:
    """Encode a list of BETH events into (WINDOW_SIZE, 48) matrix."""
    mat = np.zeros((WINDOW_SIZE, FEATURES_PER_EVENT), dtype=np.float32)
    for i, ev in enumerate(events):
        if i >= WINDOW_SIZE:
            break

        vec = _encode_event(ev)
        if vec is None:
            continue
        mat[i] = vec

    return mat


def _encode_event(ev: dict) -> np.ndarray | None:
    """Encode a single BETH event into a 48-dim feature vector."""
    vec = np.zeros(FEATURES_PER_EVENT, dtype=np.float32)
    try:
        # 1. Event subtype (25 one-hot)
        event_name = str(ev.get("eventName", "")).lower()
        subtype = EVENT_SUBTYPE_MAP.get(event_name, "other")
        from utils.features import EVENT_SUBTYPE_INDEX
        if subtype in EVENT_SUBTYPE_INDEX:
            vec[EVENT_SUBTYPE_INDEX[subtype]] = 1.0

        # 2. Process category (8 one-hot)
        proc_name = str(ev.get("processName", "")).lower()
        category = PROCESS_CATEGORY_MAP.get(proc_name, "unknown")
        from utils.features import PROCESS_CATEGORY_INDEX
        cat_idx = PROCESS_CATEGORY_INDEX.get(category, PROCESS_CATEGORY_INDEX["unknown"])
        vec[25 + cat_idx] = 1.0

        # 3. Privilege level (3 one-hot)
        # BETH doesn't have direct privilege info, infer from process name
        if proc_name in ("sudo", "su", "pkexec"):
            vec[33 + 2] = 1.0  # high
        elif proc_name in ("systemd", "sshd", "cron"):
            vec[33 + 1] = 1.0  # medium
        else:
            vec[33] = 1.0  # low

        # 4. Flags
        vec[36] = float(subtype in ("network_connect", "network_send", "network_recv",
                                     "network_listen", "network_accept"))
        vec[37] = float(subtype in ("file_write",))
        vec[38] = float(subtype in ("registry_write",))

        # 5. Time
        ts = ev.get("timestamp", 0)
        if isinstance(ts, str):
            try:
                import datetime
                dt = datetime.datetime.fromisoformat(ts)
                vec[39] = (dt.hour * 3600 + dt.minute * 60 + dt.second) / 86400.0
                dow = (dt.weekday() + 1) % 7
                vec[40 + dow] = 1.0
            except (ValueError, TypeError):
                vec[39] = 0.5
                vec[40 + 0] = 1.0
        else:
            vec[39] = 0.5
            vec[40 + 0] = 1.0

        # 6. Parent score
        vec[47] = 0.5

        return vec
    except Exception:
        return None
