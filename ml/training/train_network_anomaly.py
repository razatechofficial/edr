#!/usr/bin/env python3
"""Train an autoencoder for network connection anomaly detection.

Input:  (batch, 15) — matching ``NetworkFeatureExtractor`` in
        ``internal/detection/ml/features/network.go``
Output: (batch, 1)  — reconstruction error (anomaly score)

Anomalous connections produce high reconstruction error.

Usage:
    # Synthetic data (default):
    python train_network_anomaly.py --output-dir ./output

    # CIC-IDS2017 dataset:
    python train_network_anomaly.py --data-path /data/cicids2017.csv --output-dir ./output
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from utils.datasets import generate_synthetic_network_data, split_dataset
from utils.evaluation import evaluate_binary_classifier
from utils.features import NETWORK_FEATURE_COUNT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("train_network_anomaly")


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class NetworkAutoencoder(nn.Module):
    """Symmetric autoencoder with a bottleneck for anomaly scoring."""

    def __init__(self, input_dim: int = NETWORK_FEATURE_COUNT, latent_dim: int = 4):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, latent_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.encoder(x)
        return self.decoder(z)


class AnomalyScorer(nn.Module):
    """Wraps a trained autoencoder to output a scalar anomaly score."""

    def __init__(self, autoencoder: NetworkAutoencoder):
        super().__init__()
        self.autoencoder = autoencoder

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        recon = self.autoencoder(x)
        mse = ((x - recon) ** 2).mean(dim=1, keepdim=True)
        return mse


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train network anomaly autoencoder")
    p.add_argument("--data-path", type=str, default=None, help="Path to CIC-IDS2017 CSV")
    p.add_argument("--n-normal", type=int, default=10000, help="Synthetic normal samples")
    p.add_argument("--n-anomalous", type=int, default=3000, help="Synthetic anomalous samples")
    p.add_argument("--output-dir", type=str, default="./output")
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--batch-size", type=int, default=128)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--latent-dim", type=int, default=4, help="Bottleneck dimension")
    p.add_argument("--threshold-percentile", type=float, default=95.0,
                    help="Percentile of training reconstruction error for anomaly threshold")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def load_data(args: argparse.Namespace) -> tuple[np.ndarray, np.ndarray]:
    if args.data_path:
        logger.info("Loading network data from %s …", args.data_path)
        import pandas as pd

        df = pd.read_csv(args.data_path)
        if "Label" in df.columns:
            y = (df["Label"] != "BENIGN").astype(np.int32).values
            df = df.drop(columns=["Label"])
        else:
            y = df.iloc[:, -1].values.astype(np.int32)
            df = df.iloc[:, :-1]

        X = df.values.astype(np.float32)
        if X.shape[1] != NETWORK_FEATURE_COUNT:
            logger.warning(
                "Feature dim %d ≠ expected %d; using first %d or padding",
                X.shape[1], NETWORK_FEATURE_COUNT, NETWORK_FEATURE_COUNT,
            )
            if X.shape[1] > NETWORK_FEATURE_COUNT:
                X = X[:, :NETWORK_FEATURE_COUNT]
            else:
                pad = np.zeros((X.shape[0], NETWORK_FEATURE_COUNT - X.shape[1]), dtype=np.float32)
                X = np.hstack([X, pad])
        X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)
        return X, y

    logger.info("Generating synthetic network data …")
    return generate_synthetic_network_data(
        n_normal=args.n_normal,
        n_anomalous=args.n_anomalous,
        seed=args.seed,
    )


def train(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("Device: %s", device)

    X, y = load_data(args)
    splits = split_dataset(X, y, seed=args.seed)

    # Train autoencoder on NORMAL data only.
    normal_mask = splits["y_train"] == 0
    X_train_normal = splits["X_train"][normal_mask]
    logger.info("Training on %d normal samples (excluded %d anomalous from train set)",
                X_train_normal.shape[0], (~normal_mask).sum())

    train_ds = TensorDataset(torch.from_numpy(X_train_normal))
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)

    ae = NetworkAutoencoder(input_dim=NETWORK_FEATURE_COUNT, latent_dim=args.latent_dim).to(device)
    optimizer = torch.optim.Adam(ae.parameters(), lr=args.lr, weight_decay=1e-5)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs)
    criterion = nn.MSELoss()

    logger.info("Autoencoder parameters: %d", sum(p.numel() for p in ae.parameters()))

    best_loss = float("inf")
    for epoch in range(1, args.epochs + 1):
        ae.train()
        total_loss = 0.0
        for (batch,) in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            recon = ae(batch)
            loss = criterion(recon, batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * batch.size(0)
        total_loss /= len(X_train_normal)
        scheduler.step()

        if epoch % 5 == 0 or epoch == 1:
            logger.info("Epoch %3d/%d  mse=%.6f", epoch, args.epochs, total_loss)

        if total_loss < best_loss:
            best_loss = total_loss
            torch.save(ae.state_dict(), output_dir / "network_ae_best.pt")

    ae.load_state_dict(torch.load(output_dir / "network_ae_best.pt", weights_only=True))
    ae.eval()

    # Compute threshold from training reconstruction errors.
    with torch.no_grad():
        train_recon = ae(torch.from_numpy(X_train_normal).to(device))
        train_mse = ((torch.from_numpy(X_train_normal).to(device) - train_recon) ** 2).mean(dim=1).cpu().numpy()
    threshold = float(np.percentile(train_mse, args.threshold_percentile))
    logger.info("Anomaly threshold (%.0f-th percentile): %.6f", args.threshold_percentile, threshold)

    # Evaluate on test set.
    X_test_t = torch.from_numpy(splits["X_test"]).to(device)
    with torch.no_grad():
        test_recon = ae(X_test_t)
        test_mse = ((X_test_t - test_recon) ** 2).mean(dim=1).cpu().numpy()

    y_prob = test_mse / (test_mse.max() + 1e-10)  # normalize to ~[0,1]
    y_pred = (test_mse > threshold).astype(np.int32)

    evaluate_binary_classifier(
        splits["y_test"], y_pred, y_prob,
        model_name="network_anomaly", output_dir=output_dir,
    )

    # --- Export to ONNX ---
    onnx_path = output_dir / "network_anomaly.onnx"
    logger.info("Exporting anomaly scorer to ONNX → %s", onnx_path)

    scorer = AnomalyScorer(ae).to("cpu")
    scorer.eval()
    dummy = torch.randn(1, NETWORK_FEATURE_COUNT)
    torch.onnx.export(
        scorer,
        dummy,
        str(onnx_path),
        input_names=["input"],
        output_names=["anomaly_score"],
        dynamic_axes={"input": {0: "batch"}, "anomaly_score": {0: "batch"}},
        opset_version=15,
    )
    logger.info("ONNX model saved (%d bytes)", onnx_path.stat().st_size)

    np.save(output_dir / "network_anomaly_threshold.npy", np.array([threshold]))
    logger.info("Threshold saved → %s", output_dir / "network_anomaly_threshold.npy")

    _validate_onnx(onnx_path, splits["X_test"][:5])
    logger.info("Training complete.")


def _validate_onnx(onnx_path: Path, sample_input: np.ndarray) -> None:
    import onnxruntime as ort

    logger.info("Validating ONNX model …")
    sess = ort.InferenceSession(str(onnx_path))
    input_name = sess.get_inputs()[0].name
    output_names = [o.name for o in sess.get_outputs()]
    results = sess.run(output_names, {input_name: sample_input.astype(np.float32)})
    for name, arr in zip(output_names, results):
        arr_np = np.array(arr)
        logger.info("  Output '%s': shape=%s, sample=%s", name, arr_np.shape, arr_np[:3])
    logger.info("ONNX validation passed ✓")


if __name__ == "__main__":
    try:
        args = parse_args()
        train(args)
    except KeyboardInterrupt:
        logger.info("Interrupted")
        sys.exit(130)
    except Exception:
        logger.exception("Training failed")
        sys.exit(1)
