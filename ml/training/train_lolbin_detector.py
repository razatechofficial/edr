#!/usr/bin/env python3
"""Fileless / Living-off-the-Land Binary (LOLBin) detector.

Detects abuse of legitimate system tools (PowerShell, WMI, certutil, mshta,
regsvr32, etc.) for malicious purposes -- a dominant 2025+ attack vector.

Features (64-dim) matching Go runtime feature extractor:
  - [0:19]  Command-line suspicious flags (19 flags)
  - [19]    Base64 character run score
  - [20]    Ancestor count / 10
  - [21]    Process name LOLBin risk score
  - [22]    Parent process name LOLBin risk score
  - [23:31] Ancestor LOLBin risk scores (up to 8)
  - [32]    Child process count / 20
  - [33:39] Unused (child spawn)
  - [40]    Is script interpreter
  - [41]    Pipe count / 5
  - [42:47] Unused (script interp)
  - [48]    Registry ops / 50
  - [49:55] Unused (registry)
  - [56:63] Unused (WMI/COM)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("train_lolbin")

LOLBIN_FEATURE_DIM = 64

# Go suspiciousFlags indices (0-18)
SUSP_FLAGS = [
    "-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden",
    "-windowstyle hidden", "-bypass", "-exec bypass", "-noninteractive",
    "downloadstring", "downloadfile", "invoke-expression", "iex",
    "frombase64string", "new-object", "net.webclient", "bitstransfer",
    "start-process", "invoke-webrequest",
]

# Go knownLOLBins risk scores
KNOWN_LOLBINS = {
    "powershell.exe": 0.7, "pwsh.exe": 0.7, "cmd.exe": 0.4,
    "wscript.exe": 0.8, "cscript.exe": 0.8, "mshta.exe": 0.9,
    "regsvr32.exe": 0.8, "rundll32.exe": 0.7, "certutil.exe": 0.8,
    "msiexec.exe": 0.6, "installutil.exe": 0.8, "wmic.exe": 0.7,
    "bitsadmin.exe": 0.7, "schtasks.exe": 0.5, "at.exe": 0.5,
}

SCRIPT_INTERPRETERS = {"powershell", "pwsh", "wscript", "cscript", "mshta", "python", "perl", "ruby"}

# Go feature indices
IDX_BASE64 = 19
IDX_ANCESTOR_DEPTH = 20
IDX_PROC_RISK = 21
IDX_PARENT_RISK = 22
IDX_ANCESTOR_RISK_START = 23
IDX_CHILD_COUNT = 32
IDX_SCRIPT_INTERP = 40
IDX_PIPE_COUNT = 41
IDX_REG_OPS = 48

# Per-LOLBin category profiles mapping to Go runtime feature layout
LOLBIN_CATEGORIES = {
    "powershell": {
        "flags": [0, 1, 2, 3, 4, 5, 6, 7, 11, 12],
        "base64": True,
        "proc_risk": 0.7,
        "parent_risk": 0.0,
        "ancestor_risks": [0.0, 0.0, 0.0, 0.0],
        "script_interp": True,
        "pipe_chain": True,
        "child_spawn": True,
        "reg_ops": True,
    },
    "wmic": {
        "flags": [0, 1, 8, 9],
        "base64": False,
        "proc_risk": 0.7,
        "parent_risk": 0.0,
        "ancestor_risks": [0.0, 0.0, 0.0, 0.0],
        "script_interp": False,
        "pipe_chain": False,
        "child_spawn": True,
        "reg_ops": False,
    },
    "certutil": {
        "flags": [0, 6],
        "base64": True,
        "proc_risk": 0.8,
        "parent_risk": 0.0,
        "ancestor_risks": [0.0, 0.0, 0.0, 0.0],
        "script_interp": False,
        "pipe_chain": False,
        "child_spawn": True,
        "reg_ops": False,
    },
    "mshta": {
        "flags": [0, 1, 14],
        "base64": False,
        "proc_risk": 0.9,
        "parent_risk": 0.0,
        "ancestor_risks": [0.0, 0.0, 0.0, 0.0],
        "script_interp": True,
        "pipe_chain": False,
        "child_spawn": True,
        "reg_ops": False,
    },
    "regsvr32": {
        "flags": [0, 6, 14],
        "base64": True,
        "proc_risk": 0.8,
        "parent_risk": 0.4,
        "ancestor_risks": [0.7, 0.0, 0.0, 0.0],
        "script_interp": False,
        "pipe_chain": False,
        "child_spawn": False,
        "reg_ops": True,
    },
    "bitsadmin": {
        "flags": [0, 6, 15],
        "base64": False,
        "proc_risk": 0.7,
        "parent_risk": 0.0,
        "ancestor_risks": [0.0, 0.0, 0.0, 0.0],
        "script_interp": False,
        "pipe_chain": False,
        "child_spawn": True,
        "reg_ops": False,
    },
    "rundll32": {
        "flags": [0, 6, 14],
        "base64": True,
        "proc_risk": 0.7,
        "parent_risk": 0.4,
        "ancestor_risks": [0.7, 0.0, 0.0, 0.0],
        "script_interp": False,
        "pipe_chain": False,
        "child_spawn": True,
        "reg_ops": False,
    },
    "cscript": {
        "flags": [0, 2, 3, 7],
        "base64": False,
        "proc_risk": 0.8,
        "parent_risk": 0.0,
        "ancestor_risks": [0.0, 0.0, 0.0, 0.0],
        "script_interp": True,
        "pipe_chain": False,
        "child_spawn": True,
        "reg_ops": False,
    },
    "wscript": {
        "flags": [0, 2, 3, 7],
        "base64": False,
        "proc_risk": 0.8,
        "parent_risk": 0.0,
        "ancestor_risks": [0.0, 0.0, 0.0, 0.0],
        "script_interp": True,
        "pipe_chain": False,
        "child_spawn": True,
        "reg_ops": False,
    },
    "installutil": {
        "flags": [0, 2, 3],
        "base64": False,
        "proc_risk": 0.8,
        "parent_risk": 0.0,
        "ancestor_risks": [0.0, 0.0, 0.0, 0.0],
        "script_interp": False,
        "pipe_chain": False,
        "child_spawn": True,
        "reg_ops": False,
    },
    "cmd_abuse": {
        "flags": [0, 2, 3, 6, 7],
        "base64": False,
        "proc_risk": 0.4,
        "parent_risk": 0.7,
        "ancestor_risks": [0.7, 0.7, 0.4, 0.0],
        "script_interp": False,
        "pipe_chain": True,
        "child_spawn": True,
        "reg_ops": False,
    },
    "schtasks": {
        "flags": [0, 2],
        "base64": False,
        "proc_risk": 0.5,
        "parent_risk": 0.0,
        "ancestor_risks": [0.0, 0.0, 0.0, 0.0],
        "script_interp": False,
        "pipe_chain": False,
        "child_spawn": False,
        "reg_ops": True,
    },
}


class LOLBinDetector(nn.Module):
    def __init__(self, input_dim: int = LOLBIN_FEATURE_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def _gen_benign(rng: np.random.RandomState) -> np.ndarray:
    x = np.zeros(LOLBIN_FEATURE_DIM, dtype=np.float32)
    x[:20] = rng.uniform(0.0, 0.05, size=20)
    x[20] = rng.uniform(0.0, 0.3)
    x[21] = 0.0
    x[22] = 0.0
    x[23:31] = 0.0
    x[32] = rng.uniform(0.0, 0.3)
    x[40] = 0.0
    x[41] = 0.0
    x[48] = rng.uniform(0.0, 0.2)
    return x


def _gen_from_category(cat_name: str, rng: np.random.RandomState) -> np.ndarray:
    cat = LOLBIN_CATEGORIES[cat_name]
    x = np.zeros(LOLBIN_FEATURE_DIM, dtype=np.float32)

    noise = rng.normal(0, 0.08, size=LOLBIN_FEATURE_DIM).astype(np.float32)

    for fi in cat["flags"]:
        x[fi] = rng.uniform(0.8, 1.0)

    if cat["base64"]:
        x[IDX_BASE64] = rng.uniform(0.4, 1.0)

    x[IDX_ANCESTOR_DEPTH] = rng.uniform(0.2, 1.0)
    x[IDX_PROC_RISK] = cat["proc_risk"] + rng.uniform(-0.1, 0.1)

    parent_risk = cat["parent_risk"]
    if parent_risk > 0:
        x[IDX_PARENT_RISK] = parent_risk + rng.uniform(-0.1, 0.1)

    for i, ar in enumerate(cat["ancestor_risks"]):
        if ar > 0 and i < 8:
            x[IDX_ANCESTOR_RISK_START + i] = ar + rng.uniform(-0.1, 0.1)

    if cat["child_spawn"]:
        x[IDX_CHILD_COUNT] = rng.uniform(0.2, 1.0)

    if cat["script_interp"]:
        x[IDX_SCRIPT_INTERP] = 1.0

    if cat["pipe_chain"]:
        x[IDX_PIPE_COUNT] = rng.uniform(0.2, 0.8)

    if cat["reg_ops"]:
        x[IDX_REG_OPS] = rng.uniform(0.3, 1.0)

    x = np.clip(x + noise, 0.0, 1.0)
    return x


def generate_training_data(
    n_benign: int = 30000,
    n_malicious: int = 10000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)

    X_benign = np.array([_gen_benign(rng) for _ in range(n_benign)], dtype=np.float32)
    y_benign = np.zeros(n_benign, dtype=np.float32)

    X_mal = np.array([
        _gen_from_category(rng.choice(list(LOLBIN_CATEGORIES.keys())), rng)
        for _ in range(n_malicious)
    ], dtype=np.float32)
    y_mal = np.ones(n_malicious, dtype=np.float32)

    X = np.concatenate([X_benign, X_mal], axis=0)
    y = np.concatenate([y_benign, y_mal], axis=0)

    perm = rng.permutation(len(X))
    X, y = X[perm], y[perm]

    log.info("Training data: %d samples (%d benign, %d malicious, %d categories)",
             len(X), n_benign, n_malicious, len(LOLBIN_CATEGORIES))
    return X, y


def train(args: argparse.Namespace) -> None:
    X_np, y_np = generate_training_data(
        n_benign=args.n_benign,
        n_malicious=args.n_malicious,
        seed=args.seed,
    )
    split = int(len(X_np) * 0.8)

    X_train = torch.from_numpy(X_np[:split])
    y_train = torch.from_numpy(y_np[:split]).unsqueeze(1)
    X_test = torch.from_numpy(X_np[split:])
    y_test = torch.from_numpy(y_np[split:]).unsqueeze(1)

    model = LOLBinDetector()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.BCELoss()

    for epoch in range(args.epochs):
        model.train()
        optimizer.zero_grad()
        pred = model(X_train)
        loss = criterion(pred, y_train)
        loss.backward()
        optimizer.step()

        if (epoch + 1) % 10 == 0:
            model.eval()
            with torch.no_grad():
                val_pred = model(X_test)
                val_loss = criterion(val_pred, y_test).item()
                acc = ((val_pred > 0.5).float() == y_test).float().mean().item()
            log.info("Epoch %d/%d  val_loss=%.4f  acc=%.4f", epoch + 1, args.epochs, val_loss, acc)

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    onnx_path = output / "lolbin_detector.onnx"

    model.eval()
    dummy = torch.randn(1, LOLBIN_FEATURE_DIM)
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
    p.add_argument("--n-benign", type=int, default=30000, help="Number of benign samples")
    p.add_argument("--n-malicious", type=int, default=10000, help="Number of malicious samples")
    p.add_argument("--seed", type=int, default=42, help="Random seed")
    train(p.parse_args())


if __name__ == "__main__":
    main()
