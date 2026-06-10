"""Feature extraction functions matching the Go feature extractors.

Each encoder produces vectors with the same dimensionality and feature
ordering as the corresponding Go code in internal/detection/ml/features/.
"""

from __future__ import annotations

import math
import struct
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

# ---------------------------------------------------------------------------
# Constants mirroring internal/detection/ml/features/behavioral.go
# ---------------------------------------------------------------------------
BYTE_HISTOGRAM_SIZE = 256
ENTROPY_BINS = 16
MAX_SECTIONS = 16
STRING_FEATURE_COUNT = 8
PE_FEATURE_COUNT = 8
FORMAT_FEATURE_COUNT = 3
HEADER_FEATURE_COUNT = 2
BASE_FEATURE_COUNT = 2  # whole-file entropy + log file size
TOTAL_FILE_FEATURES = (
    BYTE_HISTOGRAM_SIZE
    + ENTROPY_BINS
    + BASE_FEATURE_COUNT
    + STRING_FEATURE_COUNT
    + PE_FEATURE_COUNT
    + MAX_SECTIONS
    + FORMAT_FEATURE_COUNT
    + HEADER_FEATURE_COUNT
)  # 311

FEATURES_PER_EVENT = 48
DEFAULT_WINDOW_SIZE = 50

NUM_EVENT_SUBTYPES = 25
NUM_PROCESS_CATS = 8
NUM_PRIV_LEVELS = 3

EVENT_SUBTYPE_INDEX: dict[str, int] = {
    "process_create": 0,
    "process_terminate": 1,
    "process_inject": 2,
    "file_create": 3,
    "file_write": 4,
    "file_delete": 5,
    "file_rename": 6,
    "file_read": 7,
    "network_connect": 8,
    "network_listen": 9,
    "network_send": 10,
    "network_receive": 11,
    "network_dns": 12,
    "registry_create": 13,
    "registry_write": 14,
    "registry_delete": 15,
    "registry_read": 16,
    "memory_alloc": 17,
    "memory_protect": 18,
    "auth_login": 19,
    "auth_logout": 20,
    "auth_privilege": 21,
    "module_load": 22,
    "mount_operation": 23,
    "ptrace_attach": 24,
}

PROCESS_CATEGORY_INDEX: dict[str, int] = {
    "system": 0,
    "browser": 1,
    "office": 2,
    "shell": 3,
    "scripting": 4,
    "compiler": 5,
    "debugger": 6,
    "unknown": 7,
}

NETWORK_FEATURE_COUNT = 15
RATC2_FEATURE_COUNT = 22

RANSOMWARE_FEATURE_KEYS = [
    "entropy_increase_rate",
    "file_rename_rate",
    "file_delete_rate",
    "file_type_change_rate",
    "known_extension_append",
    "ransom_note_similarity",
    "shadow_copy_deletion",
    "encryption_api_calls",
    "network_beacon_rate",
    "unique_file_extensions",
]
RANSOMWARE_FEATURE_COUNT = len(RANSOMWARE_FEATURE_KEYS)


# ---------------------------------------------------------------------------
# PE Feature Extractor  (matches features/file.go)
# ---------------------------------------------------------------------------
STREAM_CHUNK_SIZE = 32 * 1024
MAX_SCAN_BYTES = 100 * 1024 * 1024


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.zeros(256, dtype=np.float64)
    for b in data:
        counts[b] += 1
    n = float(len(data))
    probs = counts[counts > 0] / n
    return float(-np.sum(probs * np.log2(probs)))


def _entropy_histogram(chunk_entropies: list[float], bins: int = ENTROPY_BINS) -> np.ndarray:
    hist = np.zeros(bins, dtype=np.float32)
    if not chunk_entropies:
        return hist
    for e in chunk_entropies:
        b = int(e * bins / 8.0)
        b = max(0, min(bins - 1, b))
        hist[b] += 1
    hist /= len(chunk_entropies)
    return hist


class PEFeatureExtractor:
    """Extracts a 311-dimensional feature vector from a binary file.

    Mirrors the Go ``PEFeatureExtractor.Extract`` method in
    ``internal/detection/ml/features/file.go``.
    """

    FEATURE_DIM = TOTAL_FILE_FEATURES

    def extract(self, path: str | Path) -> np.ndarray:
        path = Path(path)
        data = path.read_bytes()
        file_size = len(data)
        scan_data = data[:MAX_SCAN_BYTES]

        byte_counts = np.zeros(256, dtype=np.uint64)
        chunk_entropies: list[float] = []
        str_stats = _StringStats()

        offset = 0
        while offset < len(scan_data):
            chunk = scan_data[offset : offset + STREAM_CHUNK_SIZE]
            for b in chunk:
                byte_counts[b] += 1
            chunk_entropies.append(_shannon_entropy(chunk))
            _scan_strings(str_stats, chunk)
            offset += STREAM_CHUNK_SIZE

        total_bytes = int(byte_counts.sum())
        feats = np.zeros(TOTAL_FILE_FEATURES, dtype=np.float32)
        idx = 0

        if total_bytes > 0:
            feats[idx : idx + BYTE_HISTOGRAM_SIZE] = (
                byte_counts.astype(np.float32) / total_bytes
            )
        idx += BYTE_HISTOGRAM_SIZE

        feats[idx : idx + ENTROPY_BINS] = _entropy_histogram(chunk_entropies)
        idx += ENTROPY_BINS

        feats[idx] = _whole_file_entropy(byte_counts, total_bytes)
        idx += 1
        feats[idx] = np.float32(math.log1p(file_size))
        idx += 1

        feats[idx + 0] = np.float32(math.log1p(str_stats.url_count))
        feats[idx + 1] = np.float32(math.log1p(str_stats.ip_count))
        feats[idx + 2] = np.float32(math.log1p(str_stats.registry_count))
        feats[idx + 3] = np.float32(math.log1p(str_stats.path_count))
        feats[idx + 4] = np.float32(math.log1p(str_stats.base64_count))
        feats[idx + 5] = np.float32(math.log1p(str_stats.total_strings))
        if str_stats.total_strings > 0:
            feats[idx + 6] = np.float32(str_stats.avg_length)
        feats[idx + 7] = _normalize_min_max(str_stats.max_length, 0, 1000)
        idx += STRING_FEATURE_COUNT

        idx += PE_FEATURE_COUNT
        idx += MAX_SECTIONS
        idx += FORMAT_FEATURE_COUNT

        return feats

    @staticmethod
    def feature_names() -> list[str]:
        names: list[str] = []
        names += [f"byte_hist_{i}" for i in range(BYTE_HISTOGRAM_SIZE)]
        names += [f"entropy_bin_{i}" for i in range(ENTROPY_BINS)]
        names += ["file_entropy", "log_file_size"]
        names += [
            "str_url_count",
            "str_ip_count",
            "str_registry_count",
            "str_path_count",
            "str_base64_count",
            "str_total_strings",
            "str_avg_length",
            "str_max_length",
        ]
        names += [
            "pe_num_sections",
            "pe_log_imports",
            "pe_has_exports",
            "pe_has_signature",
            "pe_has_debug",
            "pe_compile_age",
            "pe_avg_section_entropy",
            "pe_first_section_entropy",
        ]
        names += [f"section_entropy_{i}" for i in range(MAX_SECTIONS)]
        names += ["format_pe", "format_elf", "format_macho"]
        names += ["header_image_size", "header_virtual_raw_ratio"]
        return names


def _whole_file_entropy(counts: np.ndarray, total: int) -> float:
    if total == 0:
        return 0.0
    probs = counts[counts > 0].astype(np.float64) / total
    return float(-np.sum(probs * np.log2(probs)))


def _normalize_min_max(v: float, lo: float, hi: float) -> np.float32:
    if hi <= lo:
        return np.float32(0)
    n = (v - lo) / (hi - lo)
    return np.float32(max(0.0, min(1.0, n)))


class _StringStats:
    __slots__ = (
        "url_count",
        "ip_count",
        "registry_count",
        "path_count",
        "base64_count",
        "total_strings",
        "avg_length",
        "max_length",
        "length_sum",
    )

    def __init__(self) -> None:
        self.url_count = 0
        self.ip_count = 0
        self.registry_count = 0
        self.path_count = 0
        self.base64_count = 0
        self.total_strings = 0
        self.avg_length = 0.0
        self.max_length = 0.0
        self.length_sum = 0.0


def _scan_strings(stats: _StringStats, data: bytes) -> None:
    in_str = False
    str_len = 0
    for b in data:
        if 0x20 <= b < 0x7F:
            if not in_str:
                in_str = True
                str_len = 0
            str_len += 1
        else:
            if in_str and str_len >= 4:
                stats.total_strings += 1
                stats.length_sum += str_len
                if str_len > stats.max_length:
                    stats.max_length = float(str_len)
            in_str = False
            str_len = 0

    end = len(data) - 4
    i = 0
    while i < end:
        if data[i : i + 4] == b"http":
            stats.url_count += 1
            i += 4
            continue
        if (
            data[i : i + 1].isdigit()
            and data[i + 1 : i + 2] == b"."
            and data[i + 2 : i + 3].isdigit()
            and data[i + 3 : i + 4] == b"."
        ):
            stats.ip_count += 1
            i += 4
            continue
        if data[i : i + 2] == b"HK" and data[i + 2 : i + 3] in (b"E", b"L", b"C", b"U"):
            stats.registry_count += 1
            i += 3
            continue
        if data[i : i + 1] in (b"/", b"\\") and data[i + 1 : i + 2].isalpha():
            stats.path_count += 1
        if data[i : i + 1] == b"=" and i > 0 and _is_base64_char(data[i - 1]):
            stats.base64_count += 1
        i += 1

    if stats.total_strings > 0:
        stats.avg_length = stats.length_sum / stats.total_strings


def _is_base64_char(b: int) -> bool:
    return (
        (0x41 <= b <= 0x5A)
        or (0x61 <= b <= 0x7A)
        or (0x30 <= b <= 0x39)
        or b == 0x2B
        or b == 0x2F
    )


# ---------------------------------------------------------------------------
# Behavioral Feature Encoder  (matches features/process.go + behavioral.go)
# ---------------------------------------------------------------------------


class BehavioralFeatureEncoder:
    """Encodes event sequences into (window_size, 48) matrices.

    Mirrors the Go ``BehavioralFeatureExtractor`` in
    ``internal/detection/ml/features/process.go``.
    """

    FEATURES_PER_EVENT = FEATURES_PER_EVENT

    def __init__(self, window_size: int = DEFAULT_WINDOW_SIZE) -> None:
        self.window_size = window_size

    def encode(self, events: list[dict[str, Any]]) -> np.ndarray:
        """Return (window_size, FEATURES_PER_EVENT) float32 matrix."""
        mat = np.zeros((self.window_size, FEATURES_PER_EVENT), dtype=np.float32)
        for i in range(min(self.window_size, len(events))):
            mat[i] = self._encode_event(events[i])
        return mat

    def encode_flat(self, events: list[dict[str, Any]]) -> np.ndarray:
        return self.encode(events).flatten()

    def _encode_event(self, ev: dict[str, Any]) -> np.ndarray:
        vec = np.zeros(FEATURES_PER_EVENT, dtype=np.float32)
        pos = 0

        subtype = ev.get("subtype", "")
        if subtype in EVENT_SUBTYPE_INDEX:
            vec[pos + EVENT_SUBTYPE_INDEX[subtype]] = 1.0
        pos += NUM_EVENT_SUBTYPES

        category = ev.get("category", "unknown")
        cat_idx = PROCESS_CATEGORY_INDEX.get(category, PROCESS_CATEGORY_INDEX["unknown"])
        vec[pos + cat_idx] = 1.0
        pos += NUM_PROCESS_CATS

        priv = ev.get("privilege", "low")
        if priv == "high":
            vec[pos + 2] = 1.0
        elif priv == "medium":
            vec[pos + 1] = 1.0
        else:
            vec[pos] = 1.0
        pos += NUM_PRIV_LEVELS

        vec[pos] = float(ev.get("network_flag", 0))
        pos += 1
        vec[pos] = float(ev.get("file_write_flag", 0))
        pos += 1
        vec[pos] = float(ev.get("registry_flag", 0))
        pos += 1

        ts = ev.get("timestamp")
        if isinstance(ts, datetime):
            seconds = ts.hour * 3600 + ts.minute * 60 + ts.second
            vec[pos] = seconds / 86400.0
            pos += 1
            dow = ts.weekday()
            sun_based = (dow + 1) % 7  # Go: Sunday=0
            vec[pos + sun_based] = 1.0
        else:
            vec[pos] = ev.get("time_of_day", 0.0)
            pos += 1
            dow_idx = ev.get("day_of_week", 0)
            vec[pos + dow_idx] = 1.0
        pos += 7

        vec[pos] = ev.get("parent_score", 0.5)
        return vec


# ---------------------------------------------------------------------------
# Network Feature Encoder  (matches features/network.go)
# ---------------------------------------------------------------------------


class NetworkFeatureEncoder:
    """Encodes network connection events into 15-dim vectors.

    Mirrors the Go ``NetworkFeatureExtractor`` in
    ``internal/detection/ml/features/network.go``.
    """

    FEATURE_DIM = NETWORK_FEATURE_COUNT

    def encode(self, conn: dict[str, Any]) -> np.ndarray:
        feats = np.zeros(NETWORK_FEATURE_COUNT, dtype=np.float32)
        dest_port = int(conn.get("dest_port", 0))
        src_port = int(conn.get("src_port", 0))
        protocol = str(conn.get("protocol", "")).lower()
        domain = str(conn.get("domain", ""))
        dest_ip = str(conn.get("dest_ip", ""))

        ts = conn.get("timestamp")
        time_of_day = 0.0
        if isinstance(ts, datetime):
            time_of_day = (ts.hour * 3600 + ts.minute * 60 + ts.second) / 86400.0
        elif isinstance(ts, (int, float)):
            time_of_day = float(ts)

        log_max = math.log1p(65535)

        feats[0] = _port_category(dest_port)
        feats[1] = np.float32(math.log1p(src_port) / log_max)
        feats[2] = np.float32(math.log1p(dest_port) / log_max)
        feats[3] = np.float32(time_of_day)
        feats[4] = float(dest_port == 80)
        feats[5] = float(dest_port == 443)
        feats[6] = float(dest_port == 53)
        feats[7] = float(dest_port == 22)
        feats[8] = float(protocol == "tcp")
        feats[9] = float(protocol == "udp")
        feats[10] = float(src_port > 1024)
        feats[11] = np.float32(dest_port / 65535.0)
        feats[12] = float(len(domain) > 0)
        feats[13] = float(_is_private_ip(dest_ip))
        feats[14] = float(_is_loopback(dest_ip))

        return feats

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "dest_port_category",
            "src_port_norm",
            "dest_port_norm",
            "time_of_day",
            "is_port_80",
            "is_port_443",
            "is_port_53",
            "is_port_22",
            "protocol_tcp",
            "protocol_udp",
            "src_ephemeral",
            "dest_port_linear",
            "has_domain",
            "is_private_dest",
            "is_loopback",
        ]


# ---------------------------------------------------------------------------
# RAT C2 Feature Encoder  (matches features/ratc2.go)
# ---------------------------------------------------------------------------


class RatC2FeatureEncoder:
    """Encodes network connection events into 22-dim vectors for RAT C2
    detection.  Features [0..14] are the base 15-dim network features;
    [15..21] add byte-volume, TLS, and connection-timing features.

    Mirrors the Go ``RatC2FeatureExtractor`` in
    ``internal/detection/ml/features/ratc2.go``.
    """

    FEATURE_DIM = RATC2_FEATURE_COUNT

    def encode(self, conn: dict[str, Any]) -> np.ndarray:
        feats = np.zeros(RATC2_FEATURE_COUNT, dtype=np.float32)
        dest_port = int(conn.get("dest_port", 0))
        src_port = int(conn.get("src_port", 0))
        protocol = str(conn.get("protocol", "")).lower()
        domain = str(conn.get("domain", ""))
        dest_ip = str(conn.get("dest_ip", ""))
        bytes_in = int(conn.get("bytes_in", 0))
        bytes_out = int(conn.get("bytes_out", 0))
        duration_ms = int(conn.get("duration_ms", 0))
        ja3 = str(conn.get("ja3", ""))
        sni = str(conn.get("sni", ""))

        ts = conn.get("timestamp")
        time_of_day = 0.0
        if isinstance(ts, datetime):
            time_of_day = (ts.hour * 3600 + ts.minute * 60 + ts.second) / 86400.0
        elif isinstance(ts, (int, float)):
            time_of_day = float(ts)

        log_max = math.log1p(65535)
        log_byte_max = math.log1p(1 << 30)

        # [0..14] – base network features
        feats[0] = _port_category(dest_port)
        feats[1] = np.float32(math.log1p(src_port) / log_max)
        feats[2] = np.float32(math.log1p(dest_port) / log_max)
        feats[3] = np.float32(time_of_day)
        feats[4] = float(dest_port == 80)
        feats[5] = float(dest_port == 443)
        feats[6] = float(dest_port == 53)
        feats[7] = float(dest_port == 22)
        feats[8] = float(protocol == "tcp")
        feats[9] = float(protocol == "udp")
        feats[10] = float(src_port > 1024)
        feats[11] = np.float32(dest_port / 65535.0)
        feats[12] = float(len(domain) > 0)
        feats[13] = float(_is_private_ip(dest_ip))
        feats[14] = float(_is_loopback(dest_ip))

        # [15] – bytes_in_norm
        feats[15] = np.float32(math.log1p(bytes_in) / log_byte_max)
        # [16] – bytes_out_norm
        feats[16] = np.float32(math.log1p(bytes_out) / log_byte_max)
        # [17] – total_bytes_norm
        feats[17] = np.float32(math.log1p(bytes_in + bytes_out) / log_byte_max)
        # [18] – duration_norm
        feats[18] = np.float32(min(duration_ms / 3_600_000.0, 1.0))
        # [19] – ja3_entropy
        feats[19] = np.float32(_ja3_entropy(ja3))
        # [20] – sni_length_norm
        feats[20] = np.float32(min(len(sni) / 64.0, 1.0))
        # [21] – high_port_dest
        feats[21] = float(dest_port > 49151)

        return feats

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "dest_port_category",
            "src_port_norm",
            "dest_port_norm",
            "time_of_day",
            "is_port_80",
            "is_port_443",
            "is_port_53",
            "is_port_22",
            "protocol_tcp",
            "protocol_udp",
            "src_ephemeral",
            "dest_port_linear",
            "has_domain",
            "is_private_dest",
            "is_loopback",
            "bytes_in_norm",
            "bytes_out_norm",
            "total_bytes_norm",
            "duration_norm",
            "ja3_entropy",
            "sni_length_norm",
            "high_port_dest",
        ]


def _ja3_entropy(ja3: str) -> float:
    if not ja3:
        return 0.0
    freq: dict[str, int] = {}
    for c in ja3:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    ln = len(ja3)
    for n in freq.values():
        p = n / ln
        ent -= p * math.log2(p)
    return min(ent / 7.0, 1.0)


def _port_category(port: int) -> float:
    if port <= 1023:
        return 0.0
    if port <= 49151:
        return 0.5
    return 1.0


def _is_private_ip(ip_str: str) -> bool:
    try:
        import ipaddress

        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except (ValueError, TypeError):
        return False


def _is_loopback(ip_str: str) -> bool:
    try:
        import ipaddress

        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Ransomware Feature Encoder  (matches engine.go ransomwareFeatureKeys)
# ---------------------------------------------------------------------------


class RansomwareFeatureEncoder:
    """Encodes ransomware indicator maps into 10-dim vectors.

    Mirrors ``encodeRansomwareIndicators`` in
    ``internal/detection/ml/engine.go``.
    """

    FEATURE_DIM = RANSOMWARE_FEATURE_COUNT
    FEATURE_KEYS = RANSOMWARE_FEATURE_KEYS

    def encode(self, indicators: dict[str, float]) -> np.ndarray:
        feats = np.zeros(RANSOMWARE_FEATURE_COUNT, dtype=np.float32)
        for i, key in enumerate(RANSOMWARE_FEATURE_KEYS):
            feats[i] = np.float32(indicators.get(key, 0.0))
        return feats

    @staticmethod
    def feature_names() -> list[str]:
        return list(RANSOMWARE_FEATURE_KEYS)
