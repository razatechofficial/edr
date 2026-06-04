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


IDENTITY_ATTACK_SCENARIOS = {
    "kerberoast": {
        "desc": "Service account SPN enumeration + TGS-REP cracking",
        "auth_velocity": [0.2, 0.3, 0.1, 0.2],
        "priv_esc": [0.3, 0.4, 0.2, 0.3],
        "ticket_anomaly": [0.85, 0.9, 0.8, 0.7],
        "mfa": [0.1, 0.2, 0.1, 0.1],
        "session": [0.3, 0.4, 0.5, 0.2],
        "context": [0.2, 0.3, 0.1, 0.2],
    },
    "golden_ticket": {
        "desc": "KRBTGT hash exfil → forged TGT with arbitrary privilege",
        "auth_velocity": [0.2, 0.3, 0.1, 0.2],
        "priv_esc": [0.9, 0.95, 0.85, 0.8],
        "ticket_anomaly": [0.7, 0.85, 0.9, 0.8],
        "mfa": [0.1, 0.15, 0.1, 0.2],
        "session": [0.6, 0.8, 0.7, 0.5],
        "context": [0.3, 0.4, 0.2, 0.3],
    },
    "silver_ticket": {
        "desc": "Service NTLM hash → forged TGS for specific service",
        "auth_velocity": [0.2, 0.3, 0.2, 0.2],
        "priv_esc": [0.6, 0.7, 0.5, 0.4],
        "ticket_anomaly": [0.75, 0.8, 0.85, 0.7],
        "mfa": [0.15, 0.2, 0.15, 0.1],
        "session": [0.4, 0.5, 0.6, 0.3],
        "context": [0.2, 0.3, 0.2, 0.3],
    },
    "dcom_lateral": {
        "desc": "DCOM lateral movement with privileged user token",
        "auth_velocity": [0.3, 0.4, 0.2, 0.3],
        "priv_esc": [0.7, 0.6, 0.8, 0.5],
        "ticket_anomaly": [0.3, 0.4, 0.5, 0.3],
        "mfa": [0.2, 0.1, 0.15, 0.2],
        "session": [0.6, 0.7, 0.5, 0.4],
        "context": [0.5, 0.3, 0.4, 0.2],
    },
    "mfa_bypass": {
        "desc": "MFA fatigue bombing or token relay bypass",
        "auth_velocity": [0.6, 0.7, 0.5, 0.4],
        "priv_esc": [0.4, 0.5, 0.3, 0.2],
        "ticket_anomaly": [0.2, 0.3, 0.1, 0.2],
        "mfa": [0.85, 0.9, 0.95, 0.8],
        "session": [0.5, 0.4, 0.6, 0.3],
        "context": [0.6, 0.5, 0.7, 0.4],
    },
    "impossible_travel": {
        "desc": "Login from geographically impossible locations in short time",
        "auth_velocity": [0.9, 0.95, 0.85, 0.8],
        "priv_esc": [0.2, 0.3, 0.1, 0.2],
        "ticket_anomaly": [0.1, 0.2, 0.1, 0.15],
        "mfa": [0.3, 0.2, 0.4, 0.2],
        "session": [0.4, 0.5, 0.3, 0.2],
        "context": [0.7, 0.8, 0.6, 0.5],
    },
    "dcsync": {
        "desc": "DRSUAPI directory replication for credential harvesting",
        "auth_velocity": [0.2, 0.3, 0.3, 0.4],
        "priv_esc": [0.8, 0.7, 0.9, 0.6],
        "ticket_anomaly": [0.5, 0.6, 0.4, 0.3],
        "mfa": [0.1, 0.15, 0.1, 0.2],
        "session": [0.3, 0.4, 0.2, 0.1],
        "context": [0.4, 0.5, 0.3, 0.2],
    },
    "pass_the_hash": {
        "desc": "NTLM hash relay for lateral movement",
        "auth_velocity": [0.4, 0.5, 0.3, 0.4],
        "priv_esc": [0.5, 0.6, 0.4, 0.3],
        "ticket_anomaly": [0.3, 0.4, 0.2, 0.3],
        "mfa": [0.2, 0.15, 0.25, 0.1],
        "session": [0.5, 0.7, 0.4, 0.3],
        "context": [0.3, 0.4, 0.2, 0.3],
    },
}


def generate_synthetic_data(n: int = 20000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)

    # -- Benign baseline: normal authentication patterns --
    X = rng.beta(2, 6, (n, IDENTITY_FEATURE_DIM)).astype(np.float32)
    y = np.zeros(n, dtype=np.float32)

    n_mal = int(n * 0.20)
    mal_idx = rng.choice(n, n_mal, replace=False)

    for i in mal_idx:
        attack = rng.choice(list(IDENTITY_ATTACK_SCENARIOS.keys()))
        scenario = IDENTITY_ATTACK_SCENARIOS[attack]

        # 1) Authentication velocity (features 0-3)
        for j, v in enumerate(scenario["auth_velocity"]):
            X[i, j] = rng.uniform(v * 0.85, v * 1.15)

        # 2) Privilege escalation (features 4-7)
        for j, v in enumerate(scenario["priv_esc"]):
            X[i, 4 + j] = rng.uniform(v * 0.85, v * 1.15)

        # 3) Service ticket anomaly (features 8-11)
        for j, v in enumerate(scenario["ticket_anomaly"]):
            X[i, 8 + j] = rng.uniform(v * 0.85, v * 1.15)

        # 4) MFA patterns (features 12-15)
        for j, v in enumerate(scenario["mfa"]):
            X[i, 12 + j] = rng.uniform(v * 0.85, v * 1.15)

        # 5) Session features (features 16-19)
        for j, v in enumerate(scenario["session"]):
            X[i, 16 + j] = rng.uniform(v * 0.85, v * 1.15)

        # 6) Context features (features 20-23)
        for j, v in enumerate(scenario["context"]):
            X[i, 20 + j] = rng.uniform(v * 0.85, v * 1.15)

        y[i] = 1.0

    # Correlations: high ticket anomaly + high priv esc = credential theft
    for i in range(n):
        if X[i, 8] > 0.6 and X[i, 4] > 0.6:
            X[i, 16:18] += rng.uniform(0.05, 0.15, 2)

    np.clip(X, 0.0, 1.0, out=X)
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
