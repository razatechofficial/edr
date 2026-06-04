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


SUPPLY_CHAIN_SCENARIOS = {
    "solarwinds": {
        "desc": "Trojanized Orion update with C2 backdoor and delayed activation",
        "entropy_dev":  [0.2, 0.6, 0.8, 0.5],   # section entropy deviation
        "cert_anomaly": [0.7, 0.3, 0.5, 0.6],   # cert chain anomaly (low=bad)
        "import_dev":   [0.6, 0.7, 0.5, 0.8, 0.4, 0.3, 0.2, 0.5],
        "network_callouts": [0.8, 0.9, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2],
        "update_channel":   [0.3, 0.7, 0.2, 0.4, 0.8, 0.5, 0.6, 0.7],
    },
    "3cx_compromise": {
        "desc": "Trojanized 3CXDesktopApp with signed installer but beaconing behavior",
        "entropy_dev":  [0.3, 0.5, 0.2, 0.7],
        "cert_anomaly": [0.2, 0.1, 0.1, 0.1],   # cert looked valid
        "import_dev":   [0.5, 0.4, 0.6, 0.3, 0.7, 0.5, 0.4, 0.6],
        "network_callouts": [0.9, 0.8, 0.6, 0.7, 0.5, 0.6, 0.4, 0.5],
        "update_channel":   [0.5, 0.3, 0.6, 0.2, 0.1, 0.3, 0.2, 0.1],
    },
    "xz_utils_backdoor": {
        "desc": "SSH backdoor injected into liblzma via multi-year maintainer social engineering",
        "entropy_dev":  [0.7, 0.4, 0.3, 0.2],
        "cert_anomaly": [0.9, 0.9, 0.8, 0.7],   # no cert (OSS project)
        "import_dev":   [0.8, 0.6, 0.7, 0.5, 0.9, 0.4, 0.3, 0.2],
        "network_callouts": [0.1, 0.2, 0.1, 0.3, 0.2, 0.1, 0.1, 0.2],
        "update_channel":   [0.8, 0.7, 0.9, 0.6, 0.7, 0.5, 0.4, 0.3],
    },
    "codecov_bash": {
        "desc": "Bash uploader compromise leaking CI/CD secrets",
        "entropy_dev":  [0.4, 0.3, 0.2, 0.1],
        "cert_anomaly": [0.1, 0.1, 0.1, 0.1],
        "import_dev":   [0.2, 0.3, 0.1, 0.2, 0.1, 0.1, 0.2, 0.1],
        "network_callouts": [0.7, 0.8, 0.9, 0.7, 0.6, 0.8, 0.5, 0.7],
        "update_channel":   [0.6, 0.8, 0.5, 0.7, 0.9, 0.6, 0.5, 0.4],
    },
    "notepad_plusplus": {
        "desc": "NppCrypt plugin compromise with clipboard exfiltration",
        "entropy_dev":  [0.5, 0.7, 0.6, 0.8],
        "cert_anomaly": [0.5, 0.4, 0.6, 0.3],
        "import_dev":   [0.4, 0.6, 0.5, 0.7, 0.3, 0.5, 0.4, 0.2],
        "network_callouts": [0.3, 0.4, 0.5, 0.6, 0.7, 0.5, 0.4, 0.3],
        "update_channel":   [0.2, 0.4, 0.3, 0.5, 0.2, 0.1, 0.3, 0.2],
    },
}


def generate_synthetic_data(n: int = 20000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)

    # -- Benign baseline: normal software distributions --
    X = rng.beta(2, 5, (n, SUPPLY_CHAIN_FEATURE_DIM)).astype(np.float32)
    y = np.zeros(n, dtype=np.float32)

    n_mal = int(n * 0.20)
    mal_idx = rng.choice(n, n_mal, replace=False)

    for i in mal_idx:
        scenario = rng.choice(list(SUPPLY_CHAIN_SCENARIOS.keys()))
        s = SUPPLY_CHAIN_SCENARIOS[scenario]

        # 1) Binary entropy deviation (features 0-3)
        for j, v in enumerate(s["entropy_dev"]):
            X[i, j] = rng.uniform(v * 0.8, v * 1.2)

        # 2) Signature/certificate features (features 4-7)
        # Low values = anomalous (missing cert, invalid chain, unusual issuer)
        for j, v in enumerate(s["cert_anomaly"]):
            X[i, 4 + j] = rng.uniform(max(0, v - 0.2), min(1, v + 0.2))

        # 3) Import table features (features 8-15)
        for j, v in enumerate(s["import_dev"]):
            X[i, 8 + j] = rng.uniform(v * 0.8, v * 1.2)

        # 4) Network callout features (features 16-23)
        for j, v in enumerate(s["network_callouts"]):
            X[i, 16 + j] = rng.uniform(v * 0.8, v * 1.2)

        # 5) Update channel features (features 24-31)
        for j, v in enumerate(s["update_channel"]):
            X[i, 24 + j] = rng.uniform(v * 0.8, v * 1.2)

        y[i] = 1.0

    # Feature correlation: high entropy deviation often correlates with network callouts
    for i in range(n):
        if X[i, 0] > 0.6 and X[i, 1] > 0.5:
            X[i, 16:20] += rng.uniform(0.1, 0.25, 4)
    np.clip(X, 0.0, 1.0, out=X)

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
