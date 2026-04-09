#!/usr/bin/env python3
"""AI-generated malware detector.

Detects LLM-generated polymorphic malware by identifying statistical
patterns in code structure, string distributions, and API usage that
are characteristic of machine-generated code.

Features (48-dim):
  - Code structure entropy (12): function lengths, nesting, repetition
  - String literal profile (12): n-gram distributions, uniqueness
  - API call diversity (8): surface breadth, unusual combinations
  - Obfuscation metrics (8): encoding layers, variable naming entropy
  - Behavioral divergence (8): declared vs actual functionality gap
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("train_aigen")

AIGEN_FEATURE_DIM = 48


class AIGenDetector(nn.Module):
    def __init__(self, input_dim: int = AIGEN_FEATURE_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 96),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(96, 48),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(48, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def generate_synthetic_data(n: int = 5000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    X = rng.randn(n, AIGEN_FEATURE_DIM).astype(np.float32) * 0.3 + 0.5
    y = np.zeros(n, dtype=np.float32)

    n_aigen = int(n * 0.25)
    for i in rng.choice(n, n_aigen, replace=False):
        X[i, 0:6] = rng.uniform(0.6, 0.85, 6)    # uniform function lengths (LLM pattern)
        X[i, 6:12] = rng.uniform(0.3, 0.5, 6)     # low structural variation
        X[i, 12:18] = rng.uniform(0.7, 0.95, 6)   # high string regularity
        X[i, 24:28] = rng.uniform(0.2, 0.4, 4)    # narrow API surface
        X[i, 32:36] = rng.uniform(0.5, 0.9, 4)    # variable name entropy
        y[i] = 1.0

    return X, y


def train(args: argparse.Namespace) -> None:
    X_np, y_np = generate_synthetic_data(args.n_samples)
    split = int(len(X_np) * 0.8)

    model = AIGenDetector()
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
    onnx_path = output / "aigen_detector.onnx"

    model.eval()
    torch.onnx.export(
        model, torch.randn(1, AIGEN_FEATURE_DIM), str(onnx_path),
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
