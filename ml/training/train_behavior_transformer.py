#!/usr/bin/env python3
"""Behavioral Transformer model for event sequence anomaly detection.

Replaces/augments the LSTM with self-attention to capture long-range
dependencies in process event sequences -- critical for slow-and-low APT
attacks targeting 2025-2030 government systems.

Architecture:
  - Input: variable-length event sequences (up to 512 events, padded)
  - Positional encoding with relative time deltas
  - 4-head self-attention, 2 transformer encoder layers
  - Output: anomaly score in [0, 1]

Export: ONNX with dynamic batch axis.
"""

from __future__ import annotations

import argparse
import logging
import math
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("train_transformer")

FEATURES_PER_EVENT = 48
DEFAULT_MAX_SEQ = 512
DEFAULT_D_MODEL = 64
DEFAULT_NHEAD = 4
DEFAULT_NUM_LAYERS = 2


class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = DEFAULT_MAX_SEQ):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term[:d_model // 2])
        pe = pe.unsqueeze(0)
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:, :x.size(1)]


class BehaviorTransformer(nn.Module):
    """Transformer-based behavioral anomaly detector."""

    def __init__(self, input_dim: int = FEATURES_PER_EVENT,
                 d_model: int = DEFAULT_D_MODEL,
                 nhead: int = DEFAULT_NHEAD,
                 num_layers: int = DEFAULT_NUM_LAYERS,
                 max_seq: int = DEFAULT_MAX_SEQ):
        super().__init__()
        self.input_proj = nn.Linear(input_dim, d_model)
        self.pos_enc = PositionalEncoding(d_model, max_seq)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead,
            dim_feedforward=d_model * 4,
            dropout=0.1, batch_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(d_model // 2, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: (batch, seq_len, input_dim) -> (batch, 1)"""
        h = self.input_proj(x)
        h = self.pos_enc(h)
        h = self.encoder(h)
        pooled = h.mean(dim=1)
        return self.classifier(pooled)


def generate_synthetic_data(n_samples: int = 5000, seq_len: int = 200,
                            seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic behavioral sequences for training."""
    rng = np.random.RandomState(seed)
    X = np.zeros((n_samples, seq_len, FEATURES_PER_EVENT), dtype=np.float32)
    y = np.zeros(n_samples, dtype=np.float32)

    for i in range(n_samples):
        is_malicious = rng.random() < 0.3
        for t in range(seq_len):
            event_type = rng.randint(0, 25)
            X[i, t, event_type] = 1.0
            proc_cat = rng.randint(25, 33)
            X[i, t, proc_cat] = 1.0
            X[i, t, 33] = rng.random()  # privilege level
            X[i, t, 36:48] = rng.random(12) * 0.1  # time features

        if is_malicious:
            burst_start = rng.randint(0, seq_len - 20)
            for t in range(burst_start, min(burst_start + 20, seq_len)):
                X[i, t, 2] = 1.0   # process_inject
                X[i, t, 8] = 1.0   # network_connect
                X[i, t, 33] = 0.9  # elevated privilege
            y[i] = 1.0

    return X, y


def train(args: argparse.Namespace) -> None:
    device = torch.device("cpu")
    log.info("Training behavioral transformer on %s", device)

    seq_len = args.seq_len
    X_np, y_np = generate_synthetic_data(args.n_samples, seq_len)

    split = int(len(X_np) * 0.8)
    X_train = torch.from_numpy(X_np[:split]).to(device)
    y_train = torch.from_numpy(y_np[:split]).unsqueeze(1).to(device)
    X_test = torch.from_numpy(X_np[split:]).to(device)
    y_test = torch.from_numpy(y_np[split:]).unsqueeze(1).to(device)

    model = BehaviorTransformer(
        input_dim=FEATURES_PER_EVENT,
        d_model=args.d_model,
        nhead=args.nhead,
        num_layers=args.num_layers,
        max_seq=seq_len,
    ).to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    criterion = nn.BCELoss()

    best_loss = float("inf")
    for epoch in range(args.epochs):
        model.train()
        for i in range(0, len(X_train), args.batch_size):
            batch_X = X_train[i:i + args.batch_size]
            batch_y = y_train[i:i + args.batch_size]

            optimizer.zero_grad()
            pred = model(batch_X)
            loss = criterion(pred, batch_y)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_pred = model(X_test)
            val_loss = criterion(val_pred, y_test).item()
            acc = ((val_pred > 0.5).float() == y_test).float().mean().item()

        if val_loss < best_loss:
            best_loss = val_loss
            torch.save(model.state_dict(), str(Path(args.output_dir) / "behavior_transformer_best.pt"))

        if (epoch + 1) % 10 == 0:
            log.info("Epoch %d/%d  val_loss=%.4f  acc=%.4f", epoch + 1, args.epochs, val_loss, acc)

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    onnx_path = output / "behavior_transformer.onnx"

    model.eval()
    dummy = torch.randn(1, seq_len, FEATURES_PER_EVENT).to(device)
    torch.onnx.export(
        model, dummy, str(onnx_path),
        input_names=["input"],
        output_names=["anomaly_score"],
        dynamic_axes={"input": {0: "batch", 1: "seq_len"},
                      "anomaly_score": {0: "batch"}},
        opset_version=15,
    )
    log.info("Exported -> %s (%d bytes)", onnx_path, onnx_path.stat().st_size)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output-dir", default="./output")
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--d-model", type=int, default=DEFAULT_D_MODEL)
    p.add_argument("--nhead", type=int, default=DEFAULT_NHEAD)
    p.add_argument("--num-layers", type=int, default=DEFAULT_NUM_LAYERS)
    p.add_argument("--seq-len", type=int, default=200)
    p.add_argument("--n-samples", type=int, default=5000)
    train(p.parse_args())


if __name__ == "__main__":
    main()
