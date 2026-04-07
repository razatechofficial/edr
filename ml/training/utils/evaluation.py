"""Model evaluation metrics and visualization helpers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

logger = logging.getLogger(__name__)


def evaluate_binary_classifier(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None = None,
    model_name: str = "model",
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Compute standard binary classification metrics and optionally save plots.

    Returns a dict with precision, recall, f1, accuracy, and (if probabilities
    are provided) roc_auc.
    """
    metrics: dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }

    if y_prob is not None:
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_prob))
        except ValueError:
            metrics["roc_auc"] = 0.0

    report = classification_report(y_true, y_pred, target_names=["benign", "malicious"])
    metrics["classification_report"] = report
    logger.info("=== %s evaluation ===\n%s", model_name, report)
    for k in ("accuracy", "precision", "recall", "f1"):
        logger.info("  %s: %.4f", k, metrics[k])
    if "roc_auc" in metrics:
        logger.info("  roc_auc: %.4f", metrics["roc_auc"])

    if output_dir is not None:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        plot_confusion_matrix(
            y_true, y_pred, model_name=model_name,
            save_path=output_dir / f"{model_name}_confusion_matrix.png",
        )
        if y_prob is not None:
            plot_roc_curve(
                y_true, y_prob, model_name=model_name,
                save_path=output_dir / f"{model_name}_roc_curve.png",
            )
            plot_precision_recall_curve(
                y_true, y_prob, model_name=model_name,
                save_path=output_dir / f"{model_name}_pr_curve.png",
            )

    return metrics


def plot_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    model_name: str = "model",
    labels: list[str] | None = None,
    save_path: str | Path | None = None,
) -> None:
    labels = labels or ["benign", "malicious"]
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels, ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"{model_name} — Confusion Matrix")
    fig.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=150)
        logger.info("Saved confusion matrix → %s", save_path)
    plt.close(fig)


def plot_roc_curve(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    model_name: str = "model",
    save_path: str | Path | None = None,
) -> None:
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    roc_auc_val = auc(fpr, tpr)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, lw=2, label=f"AUC = {roc_auc_val:.4f}")
    ax.plot([0, 1], [0, 1], "k--", lw=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(f"{model_name} — ROC Curve")
    ax.legend(loc="lower right")
    fig.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=150)
        logger.info("Saved ROC curve → %s", save_path)
    plt.close(fig)


def plot_precision_recall_curve(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    model_name: str = "model",
    save_path: str | Path | None = None,
) -> None:
    precision_vals, recall_vals, _ = precision_recall_curve(y_true, y_prob)
    pr_auc = auc(recall_vals, precision_vals)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(recall_vals, precision_vals, lw=2, label=f"PR AUC = {pr_auc:.4f}")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title(f"{model_name} — Precision-Recall Curve")
    ax.legend(loc="lower left")
    fig.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=150)
        logger.info("Saved PR curve → %s", save_path)
    plt.close(fig)


def plot_feature_importance(
    importances: np.ndarray,
    feature_names: list[str],
    model_name: str = "model",
    top_n: int = 30,
    save_path: str | Path | None = None,
) -> None:
    """Plot top-N feature importances as a horizontal bar chart."""
    indices = np.argsort(importances)[::-1][:top_n]
    fig, ax = plt.subplots(figsize=(8, max(6, top_n * 0.3)))
    ax.barh(
        range(len(indices)),
        importances[indices][::-1],
        color=sns.color_palette("viridis", len(indices)),
    )
    ax.set_yticks(range(len(indices)))
    ax.set_yticklabels([feature_names[i] for i in indices][::-1])
    ax.set_xlabel("Importance")
    ax.set_title(f"{model_name} — Top-{top_n} Feature Importances")
    fig.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=150)
        logger.info("Saved feature importance → %s", save_path)
    plt.close(fig)
