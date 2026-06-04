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


def generate_synthetic_data(n: int = 20000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)

    # -- Benign baseline: human-written malware or legitimate code --
    X = rng.beta(2, 4, (n, AIGEN_FEATURE_DIM)).astype(np.float32)
    y = np.zeros(n, dtype=np.float32)

    n_aigen = int(n * 0.25)
    aigen_idx = rng.choice(n, n_aigen, replace=False)

    # AI-generated code patterns based on academic research (LLM code characteristics):
    # - Uniform function lengths (low variance)
    # - Repetitive variable naming patterns (low entropy in naming)
    # - Narrow API surface (fewer unique API calls)
    # - Formulaic comment patterns
    # - Fewer imports on average but more consistent structure
    for i in aigen_idx:
        # 1) Code structure entropy (features 0-11)
        # AI code has more uniform function lengths (low variance) vs human-written
        X[i, 0:4] = rng.uniform(0.65, 0.85, 4)      # function length uniformity (high=uniform)
        X[i, 4] = rng.uniform(0.1, 0.3)               # nesting depth variance (low)
        X[i, 5] = rng.uniform(0.7, 0.9)               # structural repetition (high=repetitive)
        X[i, 6:8] = rng.uniform(0.2, 0.4, 2)          # comment sparsity (low comments)
        X[i, 8] = rng.uniform(0.6, 0.85)              # code-to-comment ratio consistency
        X[i, 9] = rng.uniform(0.1, 0.3)               # // TODO/fixme count (unusually low)
        X[i, 10] = rng.uniform(0.6, 0.9)              # error handling patterns (repetitive)
        X[i, 11] = rng.uniform(0.1, 0.3)              # edge case density (low)

        # 2) String literal profile (features 12-23)
        X[i, 12:14] = rng.uniform(0.65, 0.9, 2)       # n-gram distribution regularity
        X[i, 14:16] = rng.uniform(0.1, 0.3, 2)        # string uniqueness (low)
        X[i, 16] = rng.uniform(0.5, 0.8)               # string length consistency
        X[i, 17] = rng.uniform(0.7, 0.9)               # encoding layer repetition
        X[i, 18:20] = rng.uniform(0.1, 0.3, 2)         # obfuscation variety (low)
        X[i, 20] = rng.uniform(0.2, 0.4)               # hardcoded IP/URL patterns (fewer)
        X[i, 21] = rng.uniform(0.6, 0.85)              # string format uniformity
        X[i, 22] = rng.uniform(0.2, 0.4)               # rare character usage (low)
        X[i, 23] = rng.uniform(0.7, 0.9)               # consistent quoting style

        # 3) API call diversity (features 24-31)
        X[i, 24:26] = rng.uniform(0.15, 0.35, 2)       # API surface breadth (narrow)
        X[i, 26] = rng.uniform(0.7, 0.9)                # unusual API combinations (repetitive)
        X[i, 27] = rng.uniform(0.1, 0.3)                # undocumented API usage (low)
        X[i, 28] = rng.uniform(0.65, 0.85)              # API call ordering consistency
        X[i, 29] = rng.uniform(0.2, 0.4)                # conditional API calls (fewer)
        X[i, 30] = rng.uniform(0.6, 0.9)                # error handling API usage
        X[i, 31] = rng.uniform(0.1, 0.25)               # reflection/self-modification (low)

        # 4) Obfuscation metrics (features 32-39)
        X[i, 32] = rng.uniform(0.4, 0.6)                # encoding layer depth (medium)
        X[i, 33] = rng.uniform(0.5, 0.8)                # variable naming entropy (medium-high)
        X[i, 34] = rng.uniform(0.1, 0.3)                # control flow obfuscation (low)
        X[i, 35] = rng.uniform(0.6, 0.85)               # string obfuscation consistency
        X[i, 36] = rng.uniform(0.2, 0.4)                # junk code insertion (low-moderate)
        X[i, 37] = rng.uniform(0.65, 0.85)              # obfuscation method consistency
        X[i, 38] = rng.uniform(0.15, 0.35)              # dead code percentage (low)
        X[i, 39] = rng.uniform(0.5, 0.75)               # encoding round complexity

        # 5) Behavioral divergence (features 40-47)
        X[i, 40] = rng.uniform(0.5, 0.8)                # syscall vs code mismatch
        X[i, 41] = rng.uniform(0.6, 0.85)               # permission elevation inconsistency
        X[i, 42] = rng.uniform(0.4, 0.7)                # network vs file I/O ratio anomaly
        X[i, 43] = rng.uniform(0.3, 0.5)                # registry operation stealth
        X[i, 44] = rng.uniform(0.5, 0.8)                # declared vs actual functionality gap
        X[i, 45] = rng.uniform(0.2, 0.4)                # defensive API bypass attempts
        X[i, 46] = rng.uniform(0.4, 0.6)                # process hollowing indicators
        X[i, 47] = rng.uniform(0.3, 0.5)                # anti-analysis evasion

        y[i] = 1.0

    np.clip(X, 0.0, 1.0, out=X)
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
