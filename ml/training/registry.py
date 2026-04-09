"""Model registry for versioning, tracking, and managing ONNX model artifacts.

Maintains a manifest.json alongside model files tracking:
- Model name, version, SHA256 hash
- Training dataset, metrics (AUC, accuracy, F1)
- Status: active, shadow, retired
- Created timestamp

Usage:
    registry = ModelRegistry("./models")
    registry.register("pe_classifier", "pe_classifier.onnx", source="ember2018",
                       metrics={"auc": 0.98})
    registry.promote("pe_classifier", "2.0.0")
    registry.rollback("pe_classifier", "1.0.0")
    registry.list_models()
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ModelVersion:
    name: str
    version: str
    file: str
    sha256: str
    source: str = ""
    status: str = "active"
    size_bytes: int = 0
    created_at: str = ""
    metrics: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ModelRegistry:
    """JSON manifest-based model registry."""

    def __init__(self, models_dir: str | Path) -> None:
        self.models_dir = Path(models_dir)
        self.manifest_path = self.models_dir / "manifest.json"
        self._manifest: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if self.manifest_path.exists():
            return json.loads(self.manifest_path.read_text())
        return {"version": "1.0", "models": []}

    def _save(self) -> None:
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(json.dumps(self._manifest, indent=2) + "\n")

    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()

    def register(self, name: str, filename: str, version: str = "",
                 source: str = "", metrics: dict[str, float] | None = None) -> ModelVersion:
        """Register a new model version in the manifest."""
        model_path = self.models_dir / filename
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        sha256 = self._sha256(model_path)
        if not version:
            existing = [m for m in self._manifest["models"] if m["name"] == name]
            version = f"{len(existing) + 1}.0.0"

        entry = ModelVersion(
            name=name,
            version=version,
            file=filename,
            sha256=sha256,
            source=source,
            status="active",
            size_bytes=model_path.stat().st_size,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            metrics=metrics or {},
        )

        models = self._manifest["models"]
        for m in models:
            if m["name"] == name and m["status"] == "active":
                m["status"] = "retired"
        models.append(entry.to_dict())
        self._manifest["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save()
        logger.info("Registered %s v%s (sha256=%s)", name, version, sha256[:12])
        return entry

    def promote(self, name: str, version: str) -> None:
        """Promote a specific version to active status."""
        for m in self._manifest["models"]:
            if m["name"] == name:
                if m["version"] == version:
                    m["status"] = "active"
                elif m["status"] == "active":
                    m["status"] = "shadow"
        self._save()
        logger.info("Promoted %s v%s to active", name, version)

    def rollback(self, name: str, target_version: str) -> None:
        """Roll back to a previous version."""
        for m in self._manifest["models"]:
            if m["name"] == name:
                if m["version"] == target_version:
                    m["status"] = "active"
                elif m["status"] == "active":
                    m["status"] = "retired"
        self._save()
        logger.info("Rolled back %s to v%s", name, target_version)

    def get_active(self, name: str) -> dict[str, Any] | None:
        """Get the currently active version of a model."""
        for m in self._manifest["models"]:
            if m["name"] == name and m["status"] == "active":
                return m
        return None

    def list_models(self) -> list[dict[str, Any]]:
        """List all model versions."""
        return self._manifest["models"]

    def diff(self, name: str, v1: str, v2: str) -> dict[str, Any]:
        """Compare metrics between two versions."""
        m1 = m2 = None
        for m in self._manifest["models"]:
            if m["name"] == name:
                if m["version"] == v1:
                    m1 = m
                elif m["version"] == v2:
                    m2 = m
        if not m1 or not m2:
            return {"error": "Version not found"}
        return {
            "name": name,
            "v1": v1,
            "v2": v2,
            "metric_diff": {
                k: round(m2.get("metrics", {}).get(k, 0) - m1.get("metrics", {}).get(k, 0), 4)
                for k in set(list(m1.get("metrics", {}).keys()) + list(m2.get("metrics", {}).keys()))
            },
            "size_diff": m2.get("size_bytes", 0) - m1.get("size_bytes", 0),
        }
