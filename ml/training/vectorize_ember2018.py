#!/usr/bin/env python3
"""Build EMBER2018 vectorized ``.dat`` files from raw ``train_features_*.jsonl``.

The official tarball only ships JSONL; ``ember.read_vectorized_features`` needs
``X_train.dat``, ``y_train.dat``, ``X_test.dat``, ``y_test.dat`` produced by
``ember.create_vectorized_features`` (CPU-heavy; can take many hours).

Usage:
    cd ml/training
    ../../.venv/bin/python vectorize_ember2018.py --data-dir /path/to/ember2018
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vectorize_ember2018")


def _repo_ml_datasets() -> Path:
    # ml/training/vectorize_ember2018.py → ml/datasets
    return Path(__file__).resolve().parents[1] / "datasets"


def _find_extracted_ember_root() -> Path | None:
    """Locate a directory under ml/datasets that already contains EMBER JSONL."""
    base = _repo_ml_datasets()
    if not base.is_dir():
        return None
    for marker in base.rglob("train_features_0.jsonl"):
        if marker.is_file():
            return marker.parent
    return None


def _print_extract_help(requested: Path) -> None:
    ds = _repo_ml_datasets()
    log.error("Not a directory: %s", requested)
    found = _find_extracted_ember_root()
    if found:
        log.error("")
        log.error("Found EMBER JSONL under this repo — use that path:")
        log.error('  --data-dir "%s"', found)
        log.error("")
    log.error("Extract the EMBER2018 tarball first (creates an ``ember2018/`` folder with JSONL). Examples:")
    log.error('  cd "%s" && tar xjf ember_dataset_2018_2.tar.bz2   # → ./ember2018/', ds)
    log.error('  cd "%s/edr_datasets" && tar xjf ember_2018.tar.bz2', ds)
    log.error("Then pass --data-dir to the folder that contains train_features_0.jsonl and test_features.jsonl.")
    log.error("(Find it with: find \"%s\" -name train_features_0.jsonl)", ds)


def main() -> None:
    p = argparse.ArgumentParser(description="Vectorize EMBER2018 JSONL → .dat (ember.create_vectorized_features)")
    p.add_argument("--data-dir", required=True, type=Path, help="Directory with train_features_0..5.jsonl and test_features.jsonl")
    p.add_argument("--feature-version", type=int, default=2)
    args = p.parse_args()

    data_dir = args.data_dir.expanduser().resolve()
    if not data_dir.is_dir():
        _print_extract_help(data_dir)
        sys.exit(1)

    required = [data_dir / f"train_features_{i}.jsonl" for i in range(6)] + [data_dir / "test_features.jsonl"]
    missing = [p for p in required if not p.is_file()]
    if missing:
        log.error("Missing expected EMBER raw files (extract ember_dataset_2018_2.tar.bz2 here):")
        for m in missing:
            log.error("  %s", m)
        sys.exit(1)

    log.info("This will take a long time (millions of JSON lines). Starting vectorization …")
    from ember_sklearn_compat import prepare_ember_for_vectorization

    prepare_ember_for_vectorization()
    import ember

    ember.create_vectorized_features(str(data_dir), feature_version=args.feature_version)
    log.info("Done. You can now run: train_pe_classifier.py --ember-dir %s", data_dir)


if __name__ == "__main__":
    main()
