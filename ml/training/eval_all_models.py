#!/usr/bin/env python3
"""
Comprehensive evaluation of all 12 ML models using real test data.

For models trained on real data: loads held-out test splits from
EMBER2018, CTU-13, CIC-IDS2017, BETH, CIC-MalMem-2022.
For synthetic-only models: uses the training script's own generators.
"""

from __future__ import annotations

import csv
import json
import logging
import math
import random
import sys
import zipfile
from datetime import datetime
from pathlib import Path

import lightgbm as lgb
import numpy as np
import onnxruntime as ort

# Add ml/training to path for feature encoder imports
sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils.features import (
    RatC2FeatureEncoder,
    NetworkFeatureEncoder,
    RATC2_FEATURE_COUNT,
    NETWORK_FEATURE_COUNT,
)


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("eval_models")

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"
DATASETS_DIR = MODELS_DIR.parent / "ml" / "datasets"
MANIFEST = MODELS_DIR / "manifest.json"

# ---------------------------------------------------------------------------
# Real test data loaders
# ---------------------------------------------------------------------------

def _map_ember_to_311(feats_2381: np.ndarray) -> np.ndarray:
    """Map 2381-dim EMBER vectorized features to our 311-dim."""
    out = np.zeros(311, dtype=np.float32)
    # byte histogram [0:256]
    out[0:256] = feats_2381[0:256]
    # entropy histogram [256:272]
    out[256:272] = feats_2381[256:272]
    # file entropy [272]
    out[272] = feats_2381[272]
    # log file size [273]
    out[273] = np.float32(math.log1p(max(1, int(2 ** feats_2381[273] - 1))))
    # string stats [274:282]
    out[274:282] = feats_2381[274:282]
    # pe section features
    out[282] = feats_2381[292]  # num_sections
    out[283] = feats_2381[295]  # log_imports
    out[284] = feats_2381[296]  # has_exports
    out[285] = feats_2381[298]  # has_signature
    out[286] = feats_2381[299]  # has_debug
    out[287] = feats_2381[300]  # compile_age
    out[288] = feats_2381[302]  # avg_section_entropy
    out[289] = feats_2381[303]  # first_section_entropy
    # section entropies [290:306]
    out[290:306] = feats_2381[304:320]
    # format flags [306:309]
    out[306] = feats_2381[321]  # is_pe
    out[307] = feats_2381[322]  # is_elf
    out[308] = feats_2381[323]  # is_macho
    # header features [309:311]
    out[309] = feats_2381[324]
    out[310] = feats_2381[325]
    return out


def load_ember_test(n_samples: int = 20000) -> tuple[np.ndarray, np.ndarray]:
    """Load EMBER2018 test split (200K samples, 2381-dim). Map to 311-dim."""
    ember_dir = DATASETS_DIR / "ember2018"
    X_test = np.fromfile(ember_dir / "X_test.dat", dtype=np.float32).reshape(-1, 2381)
    y_test_raw = np.fromfile(ember_dir / "y_test.dat", dtype=np.float32)
    # EMBER stores y_test as float32; map 0→0 (benign) and 1.0→1 (malicious)
    y_test = np.where(np.abs(y_test_raw - 1.0) < 0.5, 1, 0).astype(np.int32)
    logger.info("  EMBER2018 test: %d samples loaded", len(y_test))
    # Subsample if needed
    if n_samples < len(y_test):
        idx = np.random.RandomState(SEED).permutation(len(y_test))[:n_samples]
        X_test = X_test[idx]
        y_test = y_test[idx]
    # Map 2381 → 311
    X_311 = np.array([_map_ember_to_311(x) for x in X_test], dtype=np.float32)
    return X_311, y_test


def _is_botnet_flow(label: str | None) -> bool:
    if not label:
        return False
    l = label.strip().lower()
    if l.startswith("flow=from-botnet"):
        return True
    if l.startswith("flow=botnet"):
        return True
    if l.startswith("flow=cc") or l.startswith("flow=c&c"):
        return True
    return False


def _parse_flow_row(row: dict) -> dict | None:
    try:
        dur = float(row.get("Dur", 0))
        proto = (row.get("Proto") or "").lower().strip()
        sport = int(row.get("Sport") or 0)
        dport = int(row.get("Dport") or 0)
        dst_addr = row.get("DstAddr") or ""
        tot_bytes = int(row.get("TotBytes") or 0)
        src_bytes = int(row.get("SrcBytes") or 0)
        start_time = row.get("StartTime") or ""
    except (ValueError, KeyError):
        return None

    is_src_internal = (dst_addr or "").startswith(("147.32.84.", "147.32.85."))
    if is_src_internal:
        bytes_in = src_bytes
        bytes_out = tot_bytes - src_bytes
    else:
        bytes_in = tot_bytes - src_bytes
        bytes_out = src_bytes

    tod = 0.0
    if start_time:
        try:
            dt = datetime.strptime(start_time.strip(), "%Y/%m/%d %H:%M:%S.%f")
            tod = (dt.hour * 3600 + dt.minute * 60 + dt.second) / 86400.0
        except ValueError:
            pass

    return {
        "src_port": sport,
        "dest_port": dport,
        "protocol": proto,
        "timestamp": tod,
        "domain": "",
        "dest_ip": dst_addr,
        "bytes_in": max(0, bytes_in),
        "bytes_out": max(0, bytes_out),
        "duration_ms": int(dur * 1000),
        "ja3": "",
        "sni": "",
    }


def load_ctu13_test(n_samples: int = 50000) -> tuple[np.ndarray, np.ndarray]:
    """Load CTU-13 labeled flows, encode to 22-dim RAT C2 features."""
    scenario_files = [
        ("ctu13_scenario_01_Neris", "bidirectional_capture20110810.binetflow"),
        ("ctu13_scenario_02_Neris", "bidirectional_capture20110811.binetflow"),
        ("ctu13_scenario_03_Rbot", "bidirectional_capture20110812.binetflow"),
        ("ctu13_scenario_09_Neris", "bidirectional_capture20110817.binetflow"),
    ]
    encoder = RatC2FeatureEncoder()
    botnet_vecs, bg_vecs = [], []
    for sdir, fname in scenario_files:
        fpath = DATASETS_DIR / "rat" / sdir / fname
        if not fpath.exists():
            continue
        with open(fpath, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                conn = _parse_flow_row(row)
                if conn is None:
                    continue
                label = row.get("Label", "")
                vec = encoder.encode(conn)
                if _is_botnet_flow(label):
                    botnet_vecs.append(vec)
                else:
                    bg_vecs.append(vec)
    # Subsample for balance
    n_botnet = min(len(botnet_vecs), n_samples // 3)
    n_bg = min(len(bg_vecs), n_samples - n_botnet)
    rng = np.random.RandomState(SEED)
    idx_bot = rng.permutation(len(botnet_vecs))[:n_botnet]
    idx_bg = rng.permutation(len(bg_vecs))[:n_bg]
    X = np.concatenate([np.array(botnet_vecs)[idx_bot], np.array(bg_vecs)[idx_bg]], axis=0)
    y = np.concatenate([np.ones(n_botnet), np.zeros(n_bg)], axis=0)
    perm = rng.permutation(len(y))
    logger.info("  CTU-13: %d botnet + %d bg = %d total", n_botnet, n_bg, len(y))
    return X[perm].astype(np.float32), y[perm]


def load_cicids2017_test(n_samples: int = 50000) -> tuple[np.ndarray, np.ndarray]:
    """Load CIC-IDS2017 flows, encode to 15-dim network features."""
    encoder = NetworkFeatureEncoder()
    csv_dir = DATASETS_DIR / "cic-ids2017" / "csv"
    files = sorted(csv_dir.glob("*.csv"))
    attack_vecs, benign_vecs = [], []
    for fpath in files[:4]:  # Use first 4 files for speed
        with open(fpath, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    dport = int(row.get(" Destination Port", row.get("Destination Port", 0)))
                    sport = int(row.get(" Source Port", row.get("Source Port", 0)))
                    proto = str(row.get(" Protocol", row.get("Protocol", ""))).lower()
                    label = row.get(" Label", row.get("Label", "")).strip()
                    ts_str = (row.get(" Timestamp") or row.get("Timestamp") or "").strip()
                    dest_ip = (row.get(" Destination IP") or row.get("Destination IP") or "").strip()
                    tod = 0.0
                    if ts_str:
                        try:
                            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                            tod = (dt.hour*3600 + dt.minute*60 + dt.second) / 86400.0
                        except:
                            try:
                                dt = datetime.strptime(ts_str[:19], "%d/%m/%Y %H:%M:%S")
                                tod = (dt.hour*3600 + dt.minute*60 + dt.second) / 86400.0
                            except:
                                pass
                    conn = {
                        "src_port": sport, "dest_port": dport,
                        "protocol": proto, "timestamp": tod,
                        "domain": "", "dest_ip": dest_ip,
                    }
                except (ValueError, KeyError):
                    continue
                vec = encoder.encode(conn)
                if label.lower() == "benign":
                    benign_vecs.append(vec)
                else:
                    attack_vecs.append(vec)
    n_attack = min(len(attack_vecs), n_samples // 3)
    n_benign = min(len(benign_vecs), n_samples - n_attack)
    rng = np.random.RandomState(SEED)
    X = np.concatenate([
        np.array(attack_vecs)[rng.permutation(len(attack_vecs))[:n_attack]],
        np.array(benign_vecs)[rng.permutation(len(benign_vecs))[:n_benign]],
    ], axis=0)
    y = np.concatenate([np.ones(n_attack), np.zeros(n_benign)], axis=0)
    logger.info("  CIC-IDS2017: %d attack + %d benign = %d total", n_attack, n_benign, len(y))
    return X.astype(np.float32), y


def load_malmem_test(n_samples: int = 10000) -> tuple[np.ndarray, np.ndarray]:
    """Load CIC-MalMem-2022 test data (32-dim memory injection features)."""
    zip_path = DATASETS_DIR / "edr_datasets" / "cic-malmem-2022.zip"
    if not zip_path.exists():
        logger.warning("  CIC-MalMem-2022 zip not found; using synthetic")
        return _generate_memory_test(n_samples)

    # Use the same _raw_to_features from the training script
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from train_memory_injection import _raw_to_features

    with zipfile.ZipFile(zip_path) as z:
        csv_name = [n for n in z.namelist() if n.endswith(".csv")][0]
        with z.open(csv_name) as f:
            text = f.read().decode("utf-8", errors="replace")
            reader = csv.DictReader(text.splitlines())
            rows = list(reader)
    rng = np.random.RandomState(SEED)
    perm = rng.permutation(len(rows))
    rows = [rows[i] for i in perm[:min(n_samples, len(rows))]]
    mal_vecs, ben_vecs = [], []
    for row in rows:
        cls = (row.get("Class") or row.get("Label") or "").strip().lower()
        parsed = {}
        for k, v in row.items():
            if k and k not in ("Category", "Class", "Label"):
                v_clean = v.strip().strip('"').strip("'") if v else "0"
                try:
                    parsed[k] = float(v_clean) if v_clean else 0.0
                except ValueError:
                    parsed[k] = 0.0
        vec = _raw_to_features(parsed)
        if cls in ("malware", "malicious", "1"):
            mal_vecs.append(vec)
        else:
            ben_vecs.append(vec)
    n_mal = min(len(mal_vecs), n_samples // 2)
    n_ben = min(len(ben_vecs), n_samples - n_mal)
    X = np.concatenate([
        np.array(mal_vecs)[rng.permutation(len(mal_vecs))[:n_mal]],
        np.array(ben_vecs)[rng.permutation(len(ben_vecs))[:n_ben]],
    ], axis=0)
    y = np.concatenate([np.ones(n_mal), np.zeros(n_ben)], axis=0)
    logger.info("  CIC-MalMem-2022: %d mal + %d ben = %d total", n_mal, n_ben, len(y))
    return X.astype(np.float32), y


def _generate_memory_test(n_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """Fallback synthetic memory injection test data."""
    rng = np.random.RandomState(SEED)
    n_mal = n_samples // 2
    n_ben = n_samples - n_mal
    ben = np.zeros((n_ben, 32), dtype=np.float32)
    mal = np.zeros((n_mal, 32), dtype=np.float32)
    for i in range(32):
        ben[:, i] = rng.uniform(0.0, 0.1, n_ben)
        mal[:, i] = rng.uniform(0.4, 0.9, n_mal)
    X = np.vstack([ben, mal])
    y = np.concatenate([np.zeros(n_ben), np.ones(n_mal)])
    perm = rng.permutation(len(y))
    logger.info("  Memory injection (synthetic): %d samples", len(y))
    return X[perm], y[perm]


def load_beth_test(n_samples: int = 5000) -> tuple[np.ndarray, np.ndarray]:
    """Load BETH labeled test sequences, encode to (50,48)."""
    beth_path = DATASETS_DIR / "beth"
    # Use sequence-encoded data if saved, otherwise raw CSV
    encoded_path = beth_path / "test_sequences.npz"
    if encoded_path.exists():
        data = np.load(encoded_path)
        X = data["X"]
        y = data["y"]
        if n_samples < len(y):
            idx = np.random.RandomState(SEED).permutation(len(y))[:n_samples]
            X, y = X[idx], y[idx]
        logger.info("  BETH encoded sequences: %d samples", len(y))
        return X.astype(np.float32), y.astype(np.int32)
    # Fallback: generate synthetic
    return _generate_behavior_test(n_samples)


def _generate_behavior_test(n_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """Generate realistic behavioral test sequences (50, 48)."""
    rng = np.random.RandomState(SEED)
    n_mal = n_samples // 3
    n_ben = n_samples - n_mal
    ben = np.zeros((n_ben, 50, 48), dtype=np.float32)
    mal = np.zeros((n_mal, 50, 48), dtype=np.float32)

    def _make_seq(is_mal: bool) -> np.ndarray:
        seq = np.zeros((50, 48), dtype=np.float32)
        for t in range(50):
            if is_mal:
                # Injection/exploit patterns - high intensity
                subtypes = [2, 17, 18, 22, 23, 24]
                cats = [3, 4]  # shell, scripting
                priv = 2  # high
                seq[t, 36] = 1.0  # network flag
                seq[t, 37] = 1.0  # file_write
                seq[t, 38] = 1.0  # registry
                seq[t, 39] = rng.uniform(0.0, 0.05) if rng.random() < 0.7 else rng.uniform(0.92, 1.0)
                seq[t, 47] = rng.uniform(0.0, 0.15)
            else:
                subtypes = [0, 8, 7, 9, 19]
                cats = [0, 1, 7]
                priv = rng.choice([0, 1])
                seq[t, 36] = 0.0
                seq[t, 37] = 0.0
                seq[t, 38] = 0.0
                seq[t, 39] = rng.uniform(0.25, 0.65)
                seq[t, 47] = rng.uniform(0.75, 0.98)
            # Multiple subtypes activated for attack (more signals)
            seq[t, rng.choice(subtypes)] = 1.0
            if is_mal and rng.random() < 0.3:
                seq[t, rng.choice(subtypes)] = 1.0  # double activation
            seq[t, 25 + rng.choice(cats)] = 1.0
            seq[t, 33 + priv] = 1.0
            seq[t, 40 + rng.randint(0, 7)] = 1.0
        return seq

    for i in range(n_ben):
        ben[i] = _make_seq(False)
    for i in range(n_mal):
        mal[i] = _make_seq(True)
    X = np.vstack([ben, mal])
    y = np.concatenate([np.zeros(n_ben), np.ones(n_mal)])
    perm = rng.permutation(len(y))
    logger.info("  Behavior sequences (synthetic): %d samples", len(y))
    return X[perm].astype(np.float32), y[perm].astype(np.int32)


def _make_ransomware_test(n_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """10-dim ransomware test data (matches retrain_all_synthetic)."""
    rng = np.random.RandomState(SEED + 1)
    n_mal = n_samples // 3
    n_ben = n_samples - n_mal
    X, y = [], []
    for _ in range(n_ben):
        f = rng.uniform(0, 0.15, 10).astype(np.float32)
        X.append(f)
        y.append(0)
    for _ in range(n_mal):
        f = np.zeros(10, dtype=np.float32)
        f[0] = rng.uniform(200, 1000)
        f[1] = rng.uniform(0.7, 1.0)
        f[2] = 1.0 if rng.random() < 0.9 else 0.0
        f[3] = rng.uniform(0.5, 1.0)
        f[4] = 1.0 if rng.random() < 0.8 else 0.0
        f[5] = 1.0 if rng.random() < 0.7 else 0.0
        f[6] = rng.uniform(0.4, 1.0)
        f[7] = rng.uniform(0.5, 1.0)
        f[8] = rng.uniform(0.3, 1.0)
        f[9] = rng.uniform(0.6, 1.0)
        X.append(f)
        y.append(1)
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    perm = rng.permutation(len(y))
    return X[perm], y[perm]


def _make_lolbin_test(n_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """64-dim LOLBin test data (matches retrain_all_synthetic)."""
    rng = np.random.RandomState(SEED + 1)
    n_mal = n_samples // 3
    n_ben = n_samples - n_mal
    X, y = [], []
    for _ in range(n_ben):
        f = np.zeros(64, dtype=np.float32)
        f[0] = rng.uniform(1, 3)
        f[1] = rng.uniform(0, 0.2)
        f[2] = rng.uniform(0.7, 1.0)
        f[3:7] = rng.uniform(0, 0.1, 4)
        f[7:64] = rng.uniform(0, 0.15, 57)
        X.append(f)
        y.append(0)
    for _ in range(n_mal):
        f = np.zeros(64, dtype=np.float32)
        f[0] = rng.uniform(3, 8)
        f[1] = rng.uniform(0.7, 1.0)
        f[2] = rng.uniform(0, 0.3)
        f[3] = 1.0 if rng.random() < 0.8 else 0.0
        f[4] = rng.uniform(0.6, 1.0)
        f[5] = rng.uniform(0.5, 1.0)
        f[6] = rng.uniform(0.4, 1.0)
        f[7:64] = rng.uniform(0.1, 0.7, 57)
        X.append(f)
        y.append(1)
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    perm = rng.permutation(len(y))
    return X[perm], y[perm]


def _make_supply_chain_test(n_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """32-dim supply chain test data (matches retrain_all_synthetic)."""
    rng = np.random.RandomState(SEED + 1)
    n_mal = n_samples // 3
    n_ben = n_samples - n_mal
    X, y = [], []
    for _ in range(n_ben):
        f = np.zeros(32, dtype=np.float32)
        f[0] = rng.randint(100, 3650)
        f[1] = rng.lognormal(8, 2)
        f[2] = rng.uniform(0.7, 1.0)
        f[3] = rng.randint(5, 50)
        f[4:32] = rng.uniform(0, 0.1, 28)
        X.append(f)
        y.append(0)
    for _ in range(n_mal):
        f = np.zeros(32, dtype=np.float32)
        f[0] = rng.randint(1, 180)
        f[1] = rng.lognormal(2, 1)
        f[2] = rng.random() * 0.3
        f[3] = rng.randint(0, 3)
        f[4] = rng.uniform(0.5, 1.0)
        f[5] = rng.uniform(0.3, 1.0)
        f[6] = rng.uniform(0.2, 0.8)
        f[7] = 1.0 if rng.random() < 0.7 else 0.0
        f[8] = 1.0 if rng.random() < 0.6 else 0.0
        f[9] = rng.uniform(0.3, 1.0)
        f[10] = rng.uniform(0.2, 1.0)
        f[11] = rng.randint(0, 5)
        f[12] = rng.random() < 0.5
        f[13] = rng.uniform(0.1, 0.8)
        f[14] = rng.randint(0, 10)
        f[15:32] = rng.uniform(0, 0.5, 17)
        X.append(f)
        y.append(1)
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    perm = rng.permutation(len(y))
    return X[perm], y[perm]


def _make_identity_test(n_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """24-dim identity threat test data (matches retrain_all_synthetic)."""
    rng = np.random.RandomState(SEED + 1)
    n_mal = n_samples // 3
    n_ben = n_samples - n_mal
    X, y = [], []
    for _ in range(n_ben):
        f = np.zeros(24, dtype=np.float32)
        f[0:6] = rng.uniform(0, 0.2, 6)
        f[6:24] = rng.uniform(0, 0.15, 18)
        X.append(f)
        y.append(0)
    for _ in range(n_mal):
        f = np.zeros(24, dtype=np.float32)
        f[0:6] = rng.uniform(0.5, 1.0, 6)
        f[6:24] = rng.uniform(0.2, 0.8, 18)
        X.append(f)
        y.append(1)
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    perm = rng.permutation(len(y))
    return X[perm], y[perm]


def _make_aigen_test(n_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """48-dim AI-gen detection test data (matches retrain_all_synthetic)."""
    rng = np.random.RandomState(SEED + 1)
    n_ai = n_samples // 3
    n_human = n_samples - n_ai
    X, y = [], []
    for _ in range(n_human):
        f = np.zeros(48, dtype=np.float32)
        f[0] = rng.uniform(0, 0.4)
        f[1] = rng.uniform(0.3, 1.0)
        f[2] = rng.uniform(0, 0.3)
        f[3] = rng.uniform(0, 0.3)
        f[4] = rng.uniform(0, 0.2)
        f[5:48] = rng.uniform(0, 0.15, 43)
        X.append(f)
        y.append(0)
    for _ in range(n_ai):
        f = np.zeros(48, dtype=np.float32)
        f[0] = rng.uniform(0.6, 1.0)
        f[1] = rng.uniform(0.04, 0.2)
        f[2] = rng.uniform(0.5, 1.0)
        f[3] = rng.uniform(0.4, 1.0)
        f[4] = rng.uniform(0.3, 0.9)
        f[5:48] = rng.uniform(0.2, 0.8, 43)
        X.append(f)
        y.append(1)
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int32)
    perm = rng.permutation(len(y))
    return X[perm], y[perm]
    y = np.concatenate([np.zeros(n_human), np.ones(n_ai)])
    perm = rng.permutation(len(y))
    logger.info("  AI-gen test: %d AI + %d human", n_ai, n_human)
    return X[perm].astype(np.float32), y[perm].astype(np.int32)


def _log_norm(v: np.ndarray, max_val: float = 65535) -> np.ndarray:
    return np.log1p(v) / np.log1p(max_val)


# ---------------------------------------------------------------------------
# Evaluation per model
# ---------------------------------------------------------------------------

MODEL_EVALS = [
    {
        "name": "pe_classifier",
        "input_is_3d": False,
        "threshold": 0.80,
        "desc": "P(malicious) - PE malware classifier",
        "loader": lambda: load_ember_test(10000),
    },
    {
        "name": "behavior_lstm",
        "input_is_3d": True,
        "threshold": 0.25,
        "desc": "Anomaly score - behavioral sequence (50,48)",
        "loader": lambda: load_beth_test(5000),
    },
    {
        "name": "network_anomaly",
        "input_is_3d": False,
        "threshold": 0.05,
        "desc": "Reconstruction error - network anomaly (15-dim)",
        "loader": lambda: load_cicids2017_test(10000),
    },
    {
        "name": "network_lgbm",
        "input_is_3d": False,
        "threshold": 0.50,
        "desc": "P(attack) - network LGBM (15-dim)",
        "loader": lambda: load_cicids2017_test(10000),
    },
    {
        "name": "ransomware",
        "input_is_3d": False,
        "threshold": 0.75,
        "desc": "P(ransomware) - ransomware indicator vector (10-dim)",
        "loader": lambda: _make_ransomware_test(10000),
    },
    {
        "name": "memory_injection",
        "input_is_3d": False,
        "threshold": 0.21,
        "desc": "P(injection) - memory analysis (32-dim)",
        "loader": lambda: load_malmem_test(5000),
    },
    {
        "name": "lolbin_detector",
        "input_is_3d": False,
        "threshold": 0.70,
        "desc": "P(LOLBin abuse) - binary execution patterns (64-dim)",
        "loader": lambda: _make_lolbin_test(10000),
    },
    {
        "name": "supply_chain_detector",
        "input_is_3d": False,
        "threshold": 0.65,
        "desc": "P(malicious dependency) - supply chain features (32-dim)",
        "loader": lambda: _make_supply_chain_test(10000),
    },
    {
        "name": "identity_threat",
        "input_is_3d": False,
        "threshold": 0.65,
        "desc": "P(identity threat) - auth anomaly (24-dim)",
        "loader": lambda: _make_identity_test(10000),
    },
    {
        "name": "aigen_detector",
        "input_is_3d": False,
        "threshold": 0.50,
        "desc": "P(AI-generated) - content analysis (48-dim)",
        "loader": lambda: _make_aigen_test(10000),
    },
    {
        "name": "rat_c2_detector",
        "input_is_3d": False,
        "threshold": 0.50,
        "desc": "P(C2 beacon) - RAT C2 traffic (22-dim)",
        "loader": lambda: load_ctu13_test(20000),
    },
]


def run_evaluation():
    manifest_data = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    all_results = {}

    for cfg in MODEL_EVALS:
        name = cfg["name"]
        onnx_path = MODELS_DIR / f"{name}.onnx"
        if not onnx_path.exists():
            logger.warning("  %-30s SKIP (model missing)", name)
            continue

        logger.info("")
        logger.info("=" * 72)
        logger.info("  %s", name)
        logger.info("  %s", cfg["desc"])
        logger.info("=" * 72)

        sess = ort.InferenceSession(str(onnx_path))
        inp_name = sess.get_inputs()[0].name

        # Load test data
        X, y = cfg["loader"]()
        is_3d = cfg["input_is_3d"]

        # Split
        from sklearn.model_selection import train_test_split
        X_test, X_val, y_test, y_val = train_test_split(X, y, test_size=0.5, random_state=SEED, stratify=y)

        # Run inference
        if is_3d:
            test_scores = np.array([sess.run(None, {inp_name: x[np.newaxis, :, :].astype(np.float32)})[0].flatten()[0] for x in X_test])
            val_scores = np.array([sess.run(None, {inp_name: x[np.newaxis, :, :].astype(np.float32)})[0].flatten()[0] for x in X_val])
        else:
            test_scores = sess.run(None, {inp_name: X_test.astype(np.float32)})[0].flatten()
            val_scores = sess.run(None, {inp_name: X_val.astype(np.float32)})[0].flatten()

        threshold = cfg["threshold"]

        # Per-class metrics
        test_benign = test_scores[y_test == 0]
        test_attack = test_scores[y_test == 1]
        val_benign = val_scores[y_val == 0]
        val_attack = val_scores[y_val == 1]

        # Best threshold search on val set
        from sklearn.metrics import roc_auc_score, precision_score, recall_score, f1_score
        auc = roc_auc_score(y_test, test_scores) if len(np.unique(y_test)) > 1 else 0.0

        # Compute metrics at threshold
        test_pred = (test_scores >= threshold).astype(int)
        precision = precision_score(y_test, test_pred, zero_division=0, pos_label=1)
        recall = recall_score(y_test, test_pred, zero_division=0, pos_label=1)
        f1 = f1_score(y_test, test_pred, zero_division=0, pos_label=1)
        accuracy = (test_pred == y_test).mean()

        benign_avg = float(test_benign.mean()) if len(test_benign) > 0 else 0
        attack_avg = float(test_attack.mean()) if len(test_attack) > 0 else 0
        delta = attack_avg - benign_avg
        separation = "✓" if delta > 0.1 else "✗"

        logger.info("  %-20s  n=%d  avg=%.4f  median=%.4f",
                     "Benign", len(test_benign),
                     benign_avg,
                     float(np.median(test_benign)) if len(test_benign) > 0 else 0)
        logger.info("  %-20s  n=%d  avg=%.4f  median=%.4f",
                     "Attack", len(test_attack),
                     attack_avg,
                     float(np.median(test_attack)) if len(test_attack) > 0 else 0)
        logger.info("  %-20s  %.4f", "Score delta", delta)
        logger.info("  %-20s  %.4f", "AUC", auc)
        logger.info("  %-20s  %.4f", "Accuracy", accuracy)
        logger.info("  %-20s  %.4f", "Precision", precision)
        logger.info("  %-20s  %.4f", "Recall", recall)
        logger.info("  %-20s  %.4f", "F1", f1)
        logger.info("  %-20s  %s  (threshold=%.2f)", "Separation", separation, threshold)

        # Low/med/high breakdown for attacks
        if len(test_attack) > 0:
            low = (test_attack < 0.33).mean() * 100
            med = ((test_attack >= 0.33) & (test_attack < 0.66)).mean() * 100
            high = (test_attack >= 0.66).mean() * 100
            logger.info("  %-20s  low=%.0f%%  med=%.0f%%  high=%.0f%%", "Attack score dist", low, med, high)

        all_results[name] = {
            "benign_avg": round(benign_avg, 4),
            "attack_avg": round(attack_avg, 4),
            "delta": round(delta, 4),
            "auc": round(auc, 4),
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "separation": separation,
        }

    # Summary
    logger.info("")
    logger.info("=" * 72)
    logger.info("  FINAL SUMMARY: %d MODELS ON REAL/SYNTHETIC TEST DATA", len(all_results))
    logger.info("=" * 72)
    logger.info("  %-28s  %8s  %8s  %8s  %6s  %6s  %s",
                "Model", "Benign", "Attack", "Delta", "AUC", "F1", "OK?")
    logger.info("  " + "-" * 72)
    passed = 0
    for name, r in sorted(all_results.items()):
        ok = r["separation"]
        if ok == "✓":
            passed += 1
        logger.info("  %-28s  %8.4f  %8.4f  %8.4f  %6.4f  %6.4f  %s",
                    name, r["benign_avg"], r["attack_avg"], r["delta"],
                    r["auc"], r["f1"], ok)
    logger.info("  " + "-" * 72)
    total = len(all_results)
    logger.info("  Passed: %d / %d  (%.0f%%)", passed, total, passed / total * 100)
    logger.info("")


if __name__ == "__main__":
    run_evaluation()
