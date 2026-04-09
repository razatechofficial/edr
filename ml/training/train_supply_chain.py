#!/usr/bin/env python3
"""Supply chain attack detector.

Detects tampered software updates, compromised build pipelines, and
backdoored dependencies -- the defining threat of 2025-2030
(SolarWinds, 3CX, XZ Utils patterns).

Features (32-dim):
  - Binary entropy deviation (4): section-level entropy vs baseline
  - Signature/certificate features (4): validity, chain depth, age
  - Import table features (8): deviation from known-good, unusual DLLs
  - Network callout features (8): timing, destinations, frequency
  - Update channel features (8): hash integrity, version sequence
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("train_supply_chain")

SUPPLY_CHAIN_FEATURE_DIM = 32


class SupplyChainDetector(nn.Module):
    def __init__(self, input_dim: int = SUPPLY_CHAIN_FEATURE_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def generate_synthetic_data(n: int = 5000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    X = rng.randn(n, SUPPLY_CHAIN_FEATURE_DIM).astype(np.float32) * 0.2 + 0.3
    y = np.zeros(n, dtype=np.float32)

    n_mal = int(n * 0.15)
    for i in rng.choice(n, n_mal, replace=False):
        X[i, 0:4] += rng.uniform(0.3, 0.7, 4)   # entropy deviation
        X[i, 4:8] -= rng.uniform(0.2, 0.5, 4)    # cert anomalies
        X[i, 16:24] += rng.uniform(0.4, 0.8, 8)  # suspicious network callouts
        y[i] = 1.0

    return X, y


def train(args: argparse.Namespace) -> None:
    X_np, y_np = generate_synthetic_data(args.n_samples)
    split = int(len(X_np) * 0.8)

    model = SupplyChainDetector()
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
    onnx_path = output / "supply_chain_detector.onnx"

    model.eval()
    dummy = torch.randn(1, SUPPLY_CHAIN_FEATURE_DIM)
    torch.onnx.export(
        model, dummy, str(onnx_path),
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
