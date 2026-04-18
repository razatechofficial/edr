"""Patch elastic ``ember`` for scikit-learn >= 1.2 ``FeatureHasher`` API.

``FeatureHasher(..., input_type="string").transform([one_string])`` was valid on
older sklearn; modern sklearn requires each sample to be an *iterable of
strings*, e.g. ``transform([[one_string]])``.

On macOS, ``multiprocessing`` defaults to **spawn**, so worker processes **re-import**
``ember`` and **do not** inherit monkeypatches from the parent.  We therefore:

1. Patch ``SectionInfo.process_raw_features`` in the main process and in **each**
   worker via ``Pool(initializer=...)``.
2. Replace ``ember.vectorize_subset`` with a copy that uses that initializer.

Call :func:`prepare_ember_for_vectorization` before ``ember.create_vectorized_features``.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_SECTION_PATCHED = False
_VECTORIZE_SUBSET_PATCHED = False


def _patch_section_info() -> None:
    """Monkeypatch ``ember.features.SectionInfo.process_raw_features`` (idempotent)."""
    global _SECTION_PATCHED
    import numpy as np
    from sklearn.feature_extraction import FeatureHasher

    import ember.features as ember_features

    def process_raw_features(self: Any, raw_obj: dict) -> Any:
        sections = raw_obj["sections"]
        general = [
            len(sections),
            sum(1 for s in sections if s["size"] == 0),
            sum(1 for s in sections if s["name"] == ""),
            sum(
                1
                for s in sections
                if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]
            ),
            sum(1 for s in sections if "MEM_WRITE" in s["props"]),
        ]
        section_sizes = [(s["name"], s["size"]) for s in sections]
        section_sizes_hashed = (
            FeatureHasher(50, input_type="pair").transform([section_sizes]).toarray()[0]
        )
        section_entropy = [(s["name"], s["entropy"]) for s in sections]
        section_entropy_hashed = (
            FeatureHasher(50, input_type="pair").transform([section_entropy]).toarray()[0]
        )
        section_vsize = [(s["name"], s["vsize"]) for s in sections]
        section_vsize_hashed = (
            FeatureHasher(50, input_type="pair").transform([section_vsize]).toarray()[0]
        )
        entry = str(raw_obj["entry"])
        entry_name_hashed = (
            FeatureHasher(50, input_type="string").transform([[entry]]).toarray()[0]
        )
        characteristics = [
            p for s in sections for p in s["props"] if s["name"] == raw_obj["entry"]
        ]
        characteristics_hashed = (
            FeatureHasher(50, input_type="string")
            .transform([characteristics if characteristics else [""]])
            .toarray()[0]
        )

        return np.hstack(
            [
                general,
                section_sizes_hashed,
                section_entropy_hashed,
                section_vsize_hashed,
                entry_name_hashed,
                characteristics_hashed,
            ]
        ).astype(np.float32)

    ember_features.SectionInfo.process_raw_features = process_raw_features
    _SECTION_PATCHED = True


def _pool_worker_init() -> None:
    """Spawn/fork worker: re-apply SectionInfo patch (fresh interpreter)."""
    _patch_section_info()


def _vectorize_subset_with_pool_init(
    X_path: str,
    y_path: str,
    raw_feature_paths: list,
    extractor: Any,
    nrows: int,
) -> None:
    """Same as ``ember.vectorize_subset`` but ``Pool(initializer=_pool_worker_init)``."""
    import multiprocessing

    import numpy as np
    import tqdm

    import ember as ember_pkg

    X = np.memmap(X_path, dtype=np.float32, mode="w+", shape=(nrows, extractor.dim))
    y = np.memmap(y_path, dtype=np.float32, mode="w+", shape=nrows)
    del X, y

    pool = multiprocessing.Pool(initializer=_pool_worker_init)
    argument_iterator = (
        (irow, raw_features_string, X_path, y_path, extractor, nrows)
        for irow, raw_features_string in enumerate(
            ember_pkg.raw_feature_iterator(raw_feature_paths)
        )
    )
    try:
        for _ in tqdm.tqdm(
            pool.imap_unordered(ember_pkg.vectorize_unpack, argument_iterator),
            total=nrows,
        ):
            pass
    finally:
        pool.close()
        pool.join()


def prepare_ember_for_vectorization() -> None:
    """Patch SectionInfo + ``ember.vectorize_subset`` for sklearn >= 1.2 and macOS spawn."""
    global _VECTORIZE_SUBSET_PATCHED

    _patch_section_info()
    logger.info("Applied ember ↔ scikit-learn >= 1.2 compatibility patch (SectionInfo)")

    if _VECTORIZE_SUBSET_PATCHED:
        return

    import ember as ember_pkg

    ember_pkg.vectorize_subset = _vectorize_subset_with_pool_init
    _VECTORIZE_SUBSET_PATCHED = True
    logger.info(
        "Patched ember.vectorize_subset to re-apply SectionInfo patch in pool workers "
        "(required on macOS spawn multiprocessing)"
    )


def apply_ember_sklearn_compat_patch() -> None:
    """Backward-compatible alias: only SectionInfo in the current process."""
    _patch_section_info()
    logger.info("Applied ember ↔ scikit-learn >= 1.2 compatibility patch (SectionInfo)")
