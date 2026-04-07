#!/usr/bin/env python3
"""Train a bidirectional LSTM for process-behavior anomaly detection.

Input:  (batch, 50, 48) — 50 events × 48 features per event
Output: (batch, 1) — anomaly score ∈ [0, 1]

Matches the Go ``BehavioralFeatureExtractor`` in
``internal/detection/ml/features/process.go``.

Usage:
    # Synthetic data (default):
    python train_behavior_lstm.py --output-dir ./output

    # Real data (CSV with columns: label + 50*48 feature columns):
    python train_behavior_lstm.py --data-path /data/behavior.csv --output-dir ./output
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

from utils.datasets import generate_synthetic_behavior_data, split_dataset
from utils.evaluation import evaluate_binary_classifier
from utils.features import DEFAULT_WINDOW_SIZE, FEATURES_PER_EVENT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("train_behavior_lstm")


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class BehaviorLSTM(nn.Module):
    def __init__(
        self,
        input_dim: int = FEATURES_PER_EVENT,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
    ):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim * 2, 64),
            nn.Tanh(),
            nn.Linear(64, 1),
        )
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len, input_dim)
        lstm_out, _ = self.lstm(x)  # (batch, seq_len, hidden*2)

        attn_weights = self.attention(lstm_out)  # (batch, seq_len, 1)
        attn_weights = torch.softmax(attn_weights, dim=1)
        context = (lstm_out * attn_weights).sum(dim=1)  # (batch, hidden*2)

        return self.classifier(context)  # (batch, 1)


# ---------------------------------------------------------------------------
# Training loop
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train behavioral LSTM model")
    p.add_argument("--data-path", type=str, default=None, help="Path to real behavioral data CSV")
    p.add_argument("--n-benign", type=int, default=5000, help="Synthetic benign sequences")
    p.add_argument("--n-malicious", type=int, default=5000, help="Synthetic malicious sequences")
    p.add_argument("--window-size", type=int, default=DEFAULT_WINDOW_SIZE)
    p.add_argument("--output-dir", type=str, default="./output")
    p.add_argument("--epochs", type=int, default=30)
    p.add_argument("--batch-size", type=int, default=64)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--hidden-dim", type=int, default=128)
    p.add_argument("--num-layers", type=int, default=2)
    p.add_argument("--dropout", type=float, default=0.3)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def load_data(args: argparse.Namespace) -> tuple[np.ndarray, np.ndarray]:
    if args.data_path:
        logger.info("Loading real behavioral data from %s …", args.data_path)
        import pandas as pd

        df = pd.read_csv(args.data_path)
        y = df.iloc[:, 0].values.astype(np.int32)
        X_flat = df.iloc[:, 1:].values.astype(np.float32)
        n = X_flat.shape[0]
        X = X_flat.reshape(n, args.window_size, FEATURES_PER_EVENT)
        return X, y

    logger.info(
        "Generating synthetic behavioral data (%d benign, %d malicious) …",
        args.n_benign, args.n_malicious,
    )
    return generate_synthetic_behavior_data(
        n_benign=args.n_benign,
        n_malicious=args.n_malicious,
        window_size=args.window_size,
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
    # split_dataset expects 2D; flatten then reshape after split.
    X_flat = X.reshape(X.shape[0], -1)
    splits = split_dataset(X_flat, y, seed=args.seed)

    def to_3d(arr: np.ndarray) -> np.ndarray:
        return arr.reshape(-1, args.window_size, FEATURES_PER_EVENT)

    train_ds = TensorDataset(
        torch.from_numpy(to_3d(splits["X_train"])),
        torch.from_numpy(splits["y_train"].astype(np.float32)),
    )
    val_ds = TensorDataset(
        torch.from_numpy(to_3d(splits["X_val"])),
        torch.from_numpy(splits["y_val"].astype(np.float32)),
    )
    test_ds = TensorDataset(
        torch.from_numpy(to_3d(splits["X_test"])),
        torch.from_numpy(splits["y_test"].astype(np.float32)),
    )

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size)

    model = BehaviorLSTM(
        input_dim=FEATURES_PER_EVENT,
        hidden_dim=args.hidden_dim,
        num_layers=args.num_layers,
        dropout=args.dropout,
    ).to(device)

    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-5)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=3,
    )

    logger.info("Model parameters: %d", sum(p.numel() for p in model.parameters()))
    best_val_loss = float("inf")
    patience_counter = 0
    patience_limit = 7

    for epoch in range(1, args.epochs + 1):
        model.train()
        train_loss = 0.0
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            optimizer.zero_grad()
            out = model(X_batch).squeeze(-1)
            loss = criterion(out, y_batch)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            train_loss += loss.item() * X_batch.size(0)
        train_loss /= len(train_ds)

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                out = model(X_batch).squeeze(-1)
                val_loss += criterion(out, y_batch).item() * X_batch.size(0)
        val_loss /= len(val_ds)
        scheduler.step(val_loss)

        logger.info(
            "Epoch %3d/%d  train_loss=%.4f  val_loss=%.4f  lr=%.2e",
            epoch, args.epochs, train_loss, val_loss,
            optimizer.param_groups[0]["lr"],
        )

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            torch.save(model.state_dict(), output_dir / "behavior_lstm_best.pt")
        else:
            patience_counter += 1
            if patience_counter >= patience_limit:
                logger.info("Early stopping at epoch %d", epoch)
                break

    model.load_state_dict(torch.load(output_dir / "behavior_lstm_best.pt", weights_only=True))
    model.eval()

    all_preds: list[np.ndarray] = []
    all_probs: list[np.ndarray] = []
    with torch.no_grad():
        for X_batch, _ in test_loader:
            X_batch = X_batch.to(device)
            probs = model(X_batch).squeeze(-1).cpu().numpy()
            all_probs.append(probs)
            all_preds.append((probs >= 0.5).astype(np.int32))

    y_pred = np.concatenate(all_preds)
    y_prob = np.concatenate(all_probs)

    evaluate_binary_classifier(
        splits["y_test"], y_pred, y_prob,
        model_name="behavior_lstm", output_dir=output_dir,
    )

    # --- Export to ONNX ---
    onnx_path = output_dir / "behavior_lstm.onnx"
    logger.info("Exporting to ONNX → %s", onnx_path)

    model.to("cpu")
    dummy = torch.randn(1, args.window_size, FEATURES_PER_EVENT)
    torch.onnx.export(
        model,
        dummy,
        str(onnx_path),
        input_names=["input"],
        output_names=["score"],
        dynamic_axes={"input": {0: "batch"}, "score": {0: "batch"}},
        opset_version=15,
    )
    logger.info("ONNX model saved (%d bytes)", onnx_path.stat().st_size)

    _validate_onnx(onnx_path, dummy.numpy())
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
        logger.info("  Output '%s': shape=%s, value=%s", name, arr_np.shape, arr_np)
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
