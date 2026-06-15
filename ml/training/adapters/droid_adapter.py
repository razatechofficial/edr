"""DroidCollection adapter for AI-generated code detection.

Uses the DroidCollection dataset (1.06M code samples, 7 languages, 43 models)
from DaniilOr/DroidCollection on HuggingFace.

Extracts same 48-dim code features as aigen_code_adapter but from a much
richer dataset with human-written, machine-generated, and machine-refined code.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd

log = logging.getLogger("droid_adapter")

AIGEN_FEATURE_DIM = 48


def extract_code_features(code: str) -> np.ndarray:
    """Re-export of aigen_code_adapter.extract_code_features."""
    from adapters.aigen_code_adapter import extract_code_features as _extract
    return _extract(code)


def load_droidcollection(
    max_samples: int = 50000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Load DroidCollection and extract 48-dim code features.

    Label mapping:
      HUMAN_GENERATED → 0 (benign)
      MACHINE_GENERATED → 1 (malicious)
      MACHINE_REFINED → 1 (malicious)
      MACHINE_GENERATED_ADVERSARIAL → 1 (malicious)

    Returns (X, y) with 48-dim feature vectors and binary labels.
    """
    rng = np.random.RandomState(seed)
    parquet_path = Path(__file__).parent.parent.parent / "datasets" / "droidcollection" / "droidcollection.parquet"

    if not parquet_path.exists():
        log.error("DroidCollection parquet not found at %s", parquet_path)
        return np.array([], dtype=np.float32).reshape(0, AIGEN_FEATURE_DIM), np.array([], dtype=np.int32)

    log.info("Reading DroidCollection from %s ...", parquet_path)
    df = pd.read_parquet(parquet_path)

    # Map labels
    label_map = {
        "HUMAN_GENERATED": 0,
        "MACHINE_GENERATED": 1,
        "MACHINE_REFINED": 1,
        "MACHINE_GENERATED_ADVERSARIAL": 1,
    }
    df["label_int"] = df["Label"].map(label_map)
    df = df.dropna(subset=["label_int"])
    df["label_int"] = df["label_int"].astype(np.int32)

    # Balance: equal samples per class
    pos = df[df["label_int"] == 1]
    neg = df[df["label_int"] == 0]

    n_per_class = min(len(pos), len(neg), max_samples // 2)

    pos_sample = pos.sample(n=n_per_class, random_state=seed)
    neg_sample = neg.sample(n=n_per_class, random_state=seed)

    combined = pd.concat([pos_sample, neg_sample]).sample(frac=1, random_state=seed)

    log.info("Extracting features from %d code samples...", len(combined))
    X_list = []
    for code in combined["Code"]:
        if isinstance(code, str) and len(code) > 20:
            fv = extract_code_features(code)
            X_list.append(fv)
        else:
            X_list.append(np.zeros(AIGEN_FEATURE_DIM, dtype=np.float32))

    X = np.array(X_list, dtype=np.float32)
    y = combined["label_int"].values.astype(np.int32)

    log.info(
        "DroidCollection: %d samples (%d AI-gen, %d human) across %d languages",
        len(X), int(y.sum()), int((y == 0).sum()),
        combined["Language"].nunique() if "Language" in combined.columns else "?",
    )

    # Shuffle
    perm = rng.permutation(len(X))
    return X[perm], y[perm]


def generate_training_data(
    n_benign: int = 15000,
    n_malicious: int = 5000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate training data from DroidCollection.

    Uses real code samples directly (no synthetic generation).
    Falls back to aigen_code_adapter if DroidCollection unavailable.
    """
    X, y = load_droidcollection(max_samples=n_benign + n_malicious, seed=seed)

    if len(X) >= n_benign + n_malicious:
        return X, y

    # Fallback to HumanVsAICode if DroidCollection doesn't have enough
    log.warning(
        "DroidCollection only has %d samples, falling back to HumanVsAICode adapter",
        len(X),
    )
    from adapters.aigen_code_adapter import generate_training_data as fallback_gen
    return fallback_gen(n_benign=n_benign, n_malicious=n_malicious, seed=seed)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    X, y = generate_training_data(n_benign=2000, n_malicious=1000)
    print(f"X shape: {X.shape}, y shape: {y.shape}")
    print(f"AI-gen: {int(y.sum())}, Human: {int(len(y) - y.sum())}")
