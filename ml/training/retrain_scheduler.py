"""Automated retraining scheduler.

Monitors drift metrics from the agent, triggers containerized retraining
when conditions are met, validates new models, and pushes them to the
model registry for hot-swap deployment.

Trigger conditions (any one):
  - Feature drift score > threshold
  - Prediction drift score > threshold
  - New labeled data > N samples
  - Time since last retrain > T days
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("retrain_scheduler")


@dataclass
class RetrainConfig:
    drift_threshold: float = 2.0
    min_new_labels: int = 500
    max_days_between: int = 30
    models_dir: str = "./models"
    data_dir: str = "./data"
    keys_dir: str = "./keys"
    docker_compose_path: str = "./ml/docker-compose.yml"
    prometheus_url: str = ""
    check_interval_secs: int = 3600


class RetrainScheduler:
    """Monitors drift metrics and triggers retraining when needed."""

    def __init__(self, config: RetrainConfig):
        self.config = config
        self.last_retrain: dict[str, float] = {}
        self.new_label_counts: dict[str, int] = {}

    def check_drift_metrics(self, model_name: str) -> dict[str, float]:
        """Query drift metrics. Returns feature_drift and prediction_drift scores."""
        if not self.config.prometheus_url:
            return {"feature_drift": 0.0, "prediction_drift": 0.0}

        try:
            import urllib.request
            metrics = {}
            for metric in ("edr_ml_feature_drift_score", "edr_ml_prediction_drift_score"):
                url = (
                    f"{self.config.prometheus_url}/api/v1/query"
                    f"?query={metric}{{model=\"{model_name}\"}}"
                )
                with urllib.request.urlopen(url, timeout=10) as resp:
                    data = json.loads(resp.read())
                    results = data.get("data", {}).get("result", [])
                    if results:
                        metrics[metric.split("edr_ml_")[1]] = float(results[0]["value"][1])
            return metrics
        except Exception as exc:
            log.warning("Failed to query Prometheus: %s", exc)
            return {"feature_drift": 0.0, "prediction_drift": 0.0}

    def should_retrain(self, model_name: str) -> tuple[bool, str]:
        """Evaluate whether retraining should be triggered."""
        metrics = self.check_drift_metrics(model_name)

        if metrics.get("feature_drift", 0) > self.config.drift_threshold:
            return True, f"feature drift {metrics['feature_drift']:.2f} > {self.config.drift_threshold}"

        if metrics.get("prediction_drift", 0) > self.config.drift_threshold:
            return True, f"prediction drift {metrics['prediction_drift']:.2f} > {self.config.drift_threshold}"

        new_labels = self.new_label_counts.get(model_name, 0)
        if new_labels >= self.config.min_new_labels:
            return True, f"{new_labels} new labeled samples >= {self.config.min_new_labels}"

        last = self.last_retrain.get(model_name, 0)
        if last > 0:
            days_since = (time.time() - last) / 86400
            if days_since >= self.config.max_days_between:
                return True, f"{days_since:.0f} days since last retrain"

        return False, "no trigger conditions met"

    def trigger_retrain(self, model_name: str) -> bool:
        """Run containerized retraining for a specific model."""
        model_map = {
            "pe_classifier": "train-pe",
            "behavior_lstm": "train-behavior",
            "network_anomaly": "train-network",
            "ransomware": "train-ransomware",
        }
        service = model_map.get(model_name)
        if not service:
            log.error("No training service for model: %s", model_name)
            return False

        log.info("Triggering retrain for %s via docker-compose service %s", model_name, service)
        try:
            result = subprocess.run(
                ["docker-compose", "-f", self.config.docker_compose_path, "run", "--rm", service],
                capture_output=True, text=True, timeout=7200,
            )
            if result.returncode != 0:
                log.error("Retrain failed: %s", result.stderr[:500])
                return False
            log.info("Retrain completed for %s", model_name)
        except subprocess.TimeoutExpired:
            log.error("Retrain timed out for %s", model_name)
            return False
        except FileNotFoundError:
            log.error("docker-compose not found, cannot trigger retrain")
            return False

        self.last_retrain[model_name] = time.time()
        self.new_label_counts[model_name] = 0
        return True

    def validate_model(self, model_path: str) -> bool:
        """Validate a retrained model using ONNX checker."""
        try:
            result = subprocess.run(
                ["python3", "-m", "training", "validate", "--model-dir", str(Path(model_path).parent)],
                capture_output=True, text=True, timeout=120,
                cwd=str(Path(__file__).parent.parent),
            )
            return result.returncode == 0
        except Exception as exc:
            log.error("Validation failed: %s", exc)
            return False

    def record_new_labels(self, model_name: str, count: int) -> None:
        """Record that new analyst labels have been ingested."""
        self.new_label_counts[model_name] = self.new_label_counts.get(model_name, 0) + count

    def run_check_cycle(self) -> dict[str, str]:
        """Run one check cycle across all tracked models."""
        results = {}
        models = ["pe_classifier", "behavior_lstm", "network_anomaly", "ransomware"]

        for model in models:
            should, reason = self.should_retrain(model)
            if should:
                log.info("Retrain triggered for %s: %s", model, reason)
                success = self.trigger_retrain(model)
                results[model] = f"retrained: {success}"
            else:
                results[model] = f"skipped: {reason}"

        return results
