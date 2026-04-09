"""Dataset adapter registry.

Unified interface for loading training data from multiple sources.

Usage:
    from adapters import DatasetRegistry
    registry = DatasetRegistry()
    X, y, meta = registry.load("ember", {"data_dir": "./data/ember"})

CLI:
    python -m adapters --source ember --data-dir ./data/ember --output ./data/processed/
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

ADAPTER_MODULES = {
    "ember": "adapters.ember_adapter",
    "sorel": "adapters.sorel_adapter",
    "malwarebazaar": "adapters.malwarebazaar_adapter",
    "cape": "adapters.cape_adapter",
    "nsrl": "adapters.nsrl_adapter",
    "network": "adapters.network_adapter",
    "cic-ids2017": "adapters.network_adapter",
    "unsw-nb15": "adapters.network_adapter",
}


class DatasetRegistry:
    """Central registry for all dataset adapters."""

    def __init__(self) -> None:
        self._cache: dict[str, Any] = {}

    @staticmethod
    def available() -> list[str]:
        return sorted(ADAPTER_MODULES.keys())

    def load(
        self, source: str, config: dict[str, Any] | None = None
    ) -> tuple[np.ndarray, np.ndarray, dict]:
        """Load a dataset by source name.

        Returns (X, y, metadata) where X is the feature matrix, y is labels,
        and metadata is a dict with source info.
        """
        module_name = ADAPTER_MODULES.get(source.lower())
        if module_name is None:
            raise ValueError(
                f"Unknown source '{source}'. Available: {self.available()}"
            )

        config = config or {}
        if source.lower() in ("cic-ids2017", "unsw-nb15"):
            config.setdefault("dataset", source.lower())

        logger.info("Loading dataset '%s' via %s ...", source, module_name)
        mod = importlib.import_module(module_name)
        X, y, metadata = mod.load(config)
        logger.info("Loaded %d samples from '%s'", len(y), source)
        return X, y, metadata

    def load_multiple(
        self, sources: list[dict[str, Any]]
    ) -> tuple[np.ndarray, np.ndarray, list[dict]]:
        """Load and concatenate multiple datasets.

        Each entry: {"source": "ember", "config": {...}}
        """
        all_X: list[np.ndarray] = []
        all_y: list[np.ndarray] = []
        all_meta: list[dict] = []

        for entry in sources:
            src = entry["source"]
            cfg = entry.get("config", {})
            X, y, meta = self.load(src, cfg)
            all_X.append(X)
            all_y.append(y)
            all_meta.append(meta)

        if not all_X:
            return np.zeros((0, 0), dtype=np.float32), np.zeros(0, dtype=np.int32), []

        max_dim = max(x.shape[1] for x in all_X)
        padded = []
        for x in all_X:
            if x.shape[1] < max_dim:
                pad = np.zeros((x.shape[0], max_dim - x.shape[1]), dtype=np.float32)
                padded.append(np.hstack([x, pad]))
            else:
                padded.append(x)

        return np.vstack(padded), np.concatenate(all_y), all_meta


def main() -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")

    p = argparse.ArgumentParser(description="Dataset adapter CLI")
    p.add_argument("--source", required=True, choices=DatasetRegistry.available())
    p.add_argument("--data-dir", default="")
    p.add_argument("--data-path", default="")
    p.add_argument("--max-samples", type=int, default=0)
    p.add_argument("--output", default="./data/processed")
    args = p.parse_args()

    config: dict[str, Any] = {}
    if args.data_dir:
        config["data_dir"] = args.data_dir
    if args.data_path:
        config["data_path"] = args.data_path
    if args.max_samples:
        config["max_samples"] = args.max_samples

    registry = DatasetRegistry()
    X, y, meta = registry.load(args.source, config)

    from pathlib import Path
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    np.save(out / "X.npy", X)
    np.save(out / "y.npy", y)

    import json
    (out / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
    logger.info("Saved to %s: X=%s, y=%s", out, X.shape, y.shape)


if __name__ == "__main__":
    main()
