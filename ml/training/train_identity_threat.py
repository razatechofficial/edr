#!/usr/bin/env python3
"""Identity / credential threat model.

Detects credential theft, Kerberoasting, golden ticket attacks, MFA bypass,
and impossible-travel scenarios -- the #1 government threat vector.

Features (24-dim):
  - Authentication velocity (4): login rate, geographic checks
  - Privilege escalation (4): chain encoding, lateral movement
  - Service ticket anomaly (4): Kerberos patterns, encryption types
  - MFA patterns (4): challenge timing, bypass indicators
  - Session features (4): token reuse, duration anomaly
  - Context features (4): time-of-day, device trust, IP reputation
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("train_identity")

IDENTITY_FEATURE_DIM = 24


class IdentityThreatModel(nn.Module):
    def __init__(self, input_dim: int = IDENTITY_FEATURE_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 48),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(48, 24),
            nn.ReLU(),
            nn.Linear(24, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def generate_synthetic_data(n: int = 5000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    X = rng.randn(n, IDENTITY_FEATURE_DIM).astype(np.float32) * 0.2 + 0.3
    y = np.zeros(n, dtype=np.float32)

    n_mal = int(n * 0.2)
    for i in rng.choice(n, n_mal, replace=False):
        attack = rng.choice(["kerberoast", "golden_ticket", "mfa_bypass", "impossible_travel"])
        if attack == "kerberoast":
            X[i, 8:12] = rng.uniform(0.7, 1.0, 4)
        elif attack == "golden_ticket":
            X[i, 4:8] = rng.uniform(0.8, 1.0, 4)
            X[i, 8:10] = rng.uniform(0.6, 0.9, 2)
        elif attack == "mfa_bypass":
            X[i, 12:16] = rng.uniform(0.6, 1.0, 4)
        elif attack == "impossible_travel":
            X[i, 0:4] = rng.uniform(0.8, 1.0, 4)
        y[i] = 1.0

    return X, y


def train(args: argparse.Namespace) -> None:
    X_np, y_np = generate_synthetic_data(args.n_samples)
    split = int(len(X_np) * 0.8)

    model = IdentityThreatModel()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.BCELoss()

    X_train = torch.from_numpy(X_np[:split])
    y_train = torch.from_numpy(y_np[:split]).unsqueeze(1)
    X_test = torch.from_numpy(X_np[split:])
    y_test = torch.from_numpy(y_np[split:]).unsqueeze(1)

    for epoch in range(args.epochs):
        model.train()
        optimizer.zero_grad()
        loss = criterion(model(X_train), y_train)
        loss.backward()
        optimizer.step()

        if (epoch + 1) % 10 == 0:
            model.eval()
            with torch.no_grad():
                val_loss = criterion(model(X_test), y_test).item()
                acc = ((model(X_test) > 0.5).float() == y_test).float().mean().item()
            log.info("Epoch %d/%d  val_loss=%.4f  acc=%.4f", epoch + 1, args.epochs, val_loss, acc)

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    onnx_path = output / "identity_threat.onnx"

    model.eval()
    torch.onnx.export(
        model, torch.randn(1, IDENTITY_FEATURE_DIM), str(onnx_path),
        input_names=["input"], output_names=["score"],
        dynamic_axes={"input": {0: "batch"}, "score": {0: "batch"}},
        opset_version=15,
    )
    log.info("Exported -> %s", onnx_path)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output-dir", default="./output")
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--n-samples", type=int, default=5000)
    train(p.parse_args())


if __name__ == "__main__":
    main()
