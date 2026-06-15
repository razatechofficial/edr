"""BODMAS PE malware dataset adapter.

Maps BODMAS 2381-dim features (same feature space as EMBER) to 311-dim
features used by the pe_classifier model.

BODMAS has 57,293 malware + 77,142 benign samples from Aug 2019 - Sep 2020.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

log = logging.getLogger("bodmas_adapter")

PE_FEATURE_DIM = 311


def map_ember_to_pe(feats: np.ndarray) -> np.ndarray:
    """Map 2381 EMBER/BODMAS features to 311 PE classifier features."""
    out = np.zeros(PE_FEATURE_DIM, dtype=np.float32)
    out[0:256] = feats[0:256]
    out[256:272] = feats[256:272]
    out[272] = feats[272]
    out[273] = np.float32(np.log1p(max(1, int(2 ** feats[273] - 1))))
    out[274:282] = feats[274:282]
    out[282] = feats[292]; out[283] = feats[295]; out[284] = feats[296]
    out[285] = feats[298]; out[286] = feats[299]; out[287] = feats[300]
    out[288] = feats[302]; out[289] = feats[303]; out[290:306] = feats[304:320]
    out[306] = feats[321]; out[307] = feats[322]; out[308] = feats[323]
    out[309] = feats[324]; out[310] = feats[325]
    return out


def load_bodmas(max_benign: int = 50000, max_malware: int = 50000) -> tuple[np.ndarray, np.ndarray]:
    """Load BODMAS dataset and map to 311-dim PE features."""
    bodmas_dir = Path(__file__).parent.parent.parent / "datasets" / "bodmas" / "BODMAS"
    npz_path = bodmas_dir / "bodmas.npz"

    if not npz_path.exists():
        log.warning("BODMAS not found at %s", npz_path)
        return np.array([]), np.array([])

    data = np.load(str(npz_path))
    X_raw = data["X"]
    y = data["y"]

    # Subsample
    benign_idx = np.where(y == 0)[0]
    malware_idx = np.where(y == 1)[0]

    rng = np.random.RandomState(42)
    benign_idx = rng.choice(benign_idx, min(max_benign, len(benign_idx)), replace=False)
    malware_idx = rng.choice(malware_idx, min(max_malware, len(malware_idx)), replace=False)

    idx = np.concatenate([benign_idx, malware_idx])
    rng.shuffle(idx)

    X_raw = X_raw[idx]
    y = y[idx]

    # Map to 311-dim
    X = np.array([map_ember_to_pe(x) for x in X_raw], dtype=np.float32)

    # Clip extreme values
    X = np.clip(X, 0.0, 1.0)

    log.info("Loaded BODMAS: %d samples (%d benign, %d malware)", len(y), int((y == 0).sum()), int(y.sum()))
    return X, y


def generate_training_data(
    n_benign: int = 30000,
    n_malicious: int = 10000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate training data using BODMAS-derived statistics."""
    rng = np.random.RandomState(seed)

    X_real, y_real = load_bodmas(max_benign=n_benign, max_malware=n_malicious)

    if len(X_real) == 0:
        # Fallback: generate from synthetic stats
        log.warning("BODMAS not available, generating synthetic data")
        from utils.datasets import generate_synthetic_pe_data as gen_pe
        return gen_pe(n_normal=n_benign, n_malicious=n_malicious)

    # Use real data directly
    X_real = np.clip(X_real, 0.0, 1.0)

    # Ensure exact requested counts
    n_benign_actual = min(n_benign, int((y_real == 0).sum()))
    n_mal_actual = min(n_malicious, int(y_real.sum()))

    benign_idx = np.where(y_real == 0)[0]
    mal_idx = np.where(y_real == 1)[0]

    chosen_benign = rng.choice(benign_idx, n_benign_actual, replace=n_benign_actual > len(benign_idx))
    chosen_mal = rng.choice(mal_idx, n_mal_actual, replace=n_mal_actual > len(mal_idx))

    X = np.concatenate([X_real[chosen_benign], X_real[chosen_mal]])
    y = np.concatenate([np.zeros(n_benign_actual, dtype=np.int32), np.ones(n_mal_actual, dtype=np.int32)])

    perm = rng.permutation(len(y))
    X, y = X[perm], y[perm]

    log.info("BODMAS training data: %d samples (%d benign, %d malware)",
             len(y), int((y == 0).sum()), int(y.sum()))
    return X, y


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    X, y = generate_training_data(n_benign=10000, n_malicious=5000)
    print(f"X shape: {X.shape}, y shape: {y.shape}")
    print(f"Malware: {int(y.sum())}, Benign: {int(len(y) - y.sum())}")
    print(f"X range: [{X.min():.4f}, {X.max():.4f}]")
