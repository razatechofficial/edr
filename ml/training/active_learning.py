"""Active learning pipeline for ML model improvement.

Selects high-uncertainty samples (scores near decision threshold) for analyst
review, ingests analyst labels, and exports priority-sampled training data
with over-representation of rare attack types.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("active_learning")


@dataclass
class UncertainSample:
    sample_id: str
    model_name: str
    score: float
    threshold: float
    uncertainty: float
    features: list[float]
    metadata: dict[str, str]
    analyst_label: str = ""


class ActiveLearner:
    """Selects uncertain samples for analyst labeling and builds enriched
    training datasets."""

    def __init__(self, threshold: float = 0.5, uncertainty_band: float = 0.15):
        self.threshold = threshold
        self.uncertainty_band = uncertainty_band
        self.review_queue: list[UncertainSample] = []
        self.labeled: list[UncertainSample] = []

    def evaluate(self, sample_id: str, model_name: str, score: float,
                 features: list[float], metadata: dict[str, str] | None = None) -> bool:
        """Check if a sample falls in the uncertainty band and should be queued
        for analyst review. Returns True if queued."""
        uncertainty = abs(score - self.threshold)
        if uncertainty < self.uncertainty_band:
            sample = UncertainSample(
                sample_id=sample_id,
                model_name=model_name,
                score=score,
                threshold=self.threshold,
                uncertainty=uncertainty,
                features=features,
                metadata=metadata or {},
            )
            self.review_queue.append(sample)
            return True
        return False

    def label_sample(self, sample_id: str, label: str) -> None:
        """Apply an analyst label (tp/fp/benign/malicious) to a queued sample."""
        for i, s in enumerate(self.review_queue):
            if s.sample_id == sample_id:
                s.analyst_label = label
                self.labeled.append(s)
                self.review_queue.pop(i)
                return
        log.warning("Sample %s not found in review queue", sample_id)

    def export_review_queue(self, output_path: str) -> int:
        """Export the review queue as JSON for an analyst dashboard."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = [asdict(s) for s in self.review_queue]
        path.write_text(json.dumps(data, indent=2, default=str) + "\n")
        log.info("Exported %d samples to review queue at %s", len(data), path)
        return len(data)

    def export_labeled_dataset(self, output_dir: str) -> tuple[np.ndarray, np.ndarray]:
        """Export labeled samples as NumPy arrays for retraining."""
        if not self.labeled:
            return np.zeros((0, 0), dtype=np.float32), np.zeros(0, dtype=np.int32)

        X = np.array([s.features for s in self.labeled], dtype=np.float32)
        y = np.array([
            1 if s.analyst_label in ("tp", "malicious") else 0
            for s in self.labeled
        ], dtype=np.int32)

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        np.save(out / "X_labeled.npy", X)
        np.save(out / "y_labeled.npy", y)
        log.info("Exported %d labeled samples to %s", len(y), out)
        return X, y

    def priority_sample(self, X: np.ndarray, y: np.ndarray,
                        target_size: int, rare_class_weight: float = 3.0) -> tuple[np.ndarray, np.ndarray]:
        """Over-sample rare attack classes for balanced training."""
        if len(y) == 0:
            return X, y

        classes, counts = np.unique(y, return_counts=True)
        if len(classes) <= 1:
            return X, y

        max_count = counts.max()
        indices = []
        rng = np.random.RandomState(42)

        for cls, cnt in zip(classes, counts):
            cls_idx = np.where(y == cls)[0]
            if cnt < max_count * 0.5:
                n_oversample = int(min(cnt * rare_class_weight, target_size // len(classes)))
                sampled = rng.choice(cls_idx, n_oversample, replace=True)
                indices.extend(sampled.tolist())
            else:
                n_sample = min(len(cls_idx), target_size // len(classes))
                sampled = rng.choice(cls_idx, n_sample, replace=False)
                indices.extend(sampled.tolist())

        indices = np.array(indices)
        rng.shuffle(indices)
        return X[indices], y[indices]

    def ingest_telemetry_csv(self, csv_path: str) -> int:
        """Ingest exported telemetry CSV and evaluate samples for uncertainty."""
        count = 0
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                score = float(row.get("score", 0))
                model = row.get("model_name", "unknown")
                features_str = row.get("features", "")
                features = [float(x) for x in features_str.split(";") if x.strip()]
                sample_id = f"{model}_{row.get('timestamp', count)}"

                if self.evaluate(sample_id, model, score, features):
                    count += 1

        log.info("Ingested %d uncertain samples from %s", count, csv_path)
        return count
