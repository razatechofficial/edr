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


EVENT_TYPES = {
    "process_create":    0,   # process creation
    "process_exit":      1,   # process termination
    "process_inject":    2,   # injection into another process
    "thread_create":     3,   # thread creation
    "thread_exit":       4,   # thread termination
    "file_open":         5,   # file open
    "file_write":        6,   # file write
    "file_delete":       7,   # file deletion
    "file_rename":       8,   # file rename
    "reg_read":          9,   # registry read
    "reg_write":        10,   # registry write
    "reg_delete":       11,   # registry key deletion
    "net_connect":      12,   # outbound network connection
    "net_listen":       13,   # listening socket
    "net_dns":          14,   # DNS query
    "net_http":         15,   # HTTP(S) request
    "dll_load":         16,   # DLL/so loading
    "dll_inject":       17,   # DLL injection
    "mem_alloc":        18,   # memory allocation (RWX)
    "mem_protect":      19,   # memory protection change
    "proc_suspend":     20,   # process suspension
    "proc_resume":      21,   # process resume
    "service_create":   22,   # service installation
    "service_start":    23,   # service start
    "wmi_exec":         24,   # WMI execution
}

# Process category distributions (features 25-33)
PROC_CATEGORY_MAP = {
    "system":       {"idx": 25, "benign_p": 0.25},
    "browser":      {"idx": 26, "benign_p": 0.15},
    "office":       {"idx": 27, "benign_p": 0.10},
    "dev_tool":     {"idx": 28, "benign_p": 0.08},
    "network_tool": {"idx": 29, "benign_p": 0.05},
    "script_host":  {"idx": 30, "benign_p": 0.12},
    "scheduler":    {"idx": 31, "benign_p": 0.03},
    "update_svc":   {"idx": 32, "benign_p": 0.07},
    "other":        {"idx": 33, "benign_p": 0.15},
}

ATTACK_PATTERNS = {
    "credential_theft": {
        "desc": "LSASS dump via Procdump or MiniDump",
        "events":    ["process_create", "mem_alloc", "mem_protect", "file_write"],
        "proc_cats": ["dev_tool", "system"],
        "duration":  15,
    },
    "lateral_movement_wmi": {
        "desc": "WMI lateral movement with remote process creation",
        "events":    ["wmi_exec", "process_create", "net_connect", "net_dns"],
        "proc_cats": ["script_host", "system"],
        "duration":  30,
    },
    "persistence_service": {
        "desc": "Malicious service installation with hidden service",
        "events":    ["service_create", "service_start", "reg_write", "file_write"],
        "proc_cats": ["system", "scheduler"],
        "duration":  20,
    },
    "data_exfiltration": {
        "desc": "Large file read + network upload to external host",
        "events":    ["file_open", "file_write", "net_connect", "net_http", "net_dns"],
        "proc_cats": ["browser", "network_tool"],
        "duration":  40,
    },
    "ransomware_encryption": {
        "desc": "Mass file encryption with extension changes",
        "events":    ["file_open", "file_write", "file_rename", "file_delete", "thread_create"],
        "proc_cats": ["other", "system"],
        "duration":  50,
    },
    "c2_beaconing": {
        "desc": "Periodic HTTPS beaconing to C2 with DNS resolution",
        "events":    ["net_dns", "net_connect", "net_http", "dll_load"],
        "proc_cats": ["browser", "network_tool", "script_host"],
        "duration":  60,
    },
    "code_injection": {
        "desc": "Classic process injection with RWX allocation",
        "events":    ["mem_alloc", "mem_protect", "process_inject", "thread_create", "dll_inject"],
        "proc_cats": ["dev_tool", "script_host"],
        "duration":  25,
    },
    "reconnaissance": {
        "desc": "Active Directory discovery with network scanning",
        "events":    ["process_create", "net_dns", "net_connect", "reg_read", "thread_create"],
        "proc_cats": ["network_tool", "script_host"],
        "duration":  35,
    },
}


def generate_synthetic_data(n_samples: int = 10000, seq_len: int = 256,
                            seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Generate realistic behavioral event sequences for training."""
    rng = np.random.RandomState(seed)
    X = np.zeros((n_samples, seq_len, FEATURES_PER_EVENT), dtype=np.float32)
    y = np.zeros(n_samples, dtype=np.float32)

    event_names = list(EVENT_TYPES.keys())
    event_ids = [EVENT_TYPES[k] for k in event_names]
    event_probabilities = np.array([0.18, 0.10, 0.01, 0.05, 0.03, 0.10, 0.08, 0.02,
                                    0.01, 0.06, 0.05, 0.01, 0.05, 0.02, 0.04, 0.03,
                                    0.05, 0.005, 0.005, 0.005, 0.005, 0.003, 0.01, 0.01, 0.005])
    event_probabilities /= event_probabilities.sum()

    cat_names = list(PROC_CATEGORY_MAP.keys())
    cat_ids = [PROC_CATEGORY_MAP[k]["idx"] for k in cat_names]
    cat_probs = np.array([PROC_CATEGORY_MAP[k]["benign_p"] for k in cat_names])
    cat_probs /= cat_probs.sum()

    for i in range(n_samples):
        is_malicious = rng.random() < 0.30

        # Generate baseline benign event sequence
        for t in range(seq_len):
            # Pick event type from natural distribution
            ev_type = rng.choice(event_ids, p=event_probabilities)
            X[i, t, ev_type] = 1.0

            # Process category
            proc_cat = rng.choice(cat_ids, p=cat_probs)
            X[i, t, proc_cat - 25] = 1.0  # normalize to 0-based within section

            # Privilege level (feature 34)
            X[i, t, 34] = rng.beta(1.5, 8.0) if rng.random() < 0.95 else rng.beta(8.0, 1.5)

            # Integrity level (feature 35)
            X[i, t, 35] = rng.choice([0.1, 0.3, 0.6, 0.9], p=[0.3, 0.4, 0.2, 0.1])

            # Time-related features (features 36-47)
            X[i, t, 36] = rng.uniform(0.0, 1.0)     # inter-arrival time (normalized)
            X[i, t, 37] = rng.uniform(0.0, 0.5)     # CPU time
            X[i, t, 38] = rng.beta(2.0, 5.0)        # working set size
            X[i, t, 39] = rng.uniform(0.0, 0.3)     # page fault rate
            X[i, t, 40] = rng.beta(1.5, 1.5)        # handle count
            X[i, t, 41] = rng.uniform(0.0, 0.2)     # thread count
            X[i, t, 42] = rng.uniform(0.0, 0.5)     # subprocess count
            X[i, t, 43] = rng.choice([0.0, 0.5, 1.0])  # session type
            X[i, t, 44] = rng.beta(1.0, 3.0)        # time since boot
            X[i, t, 45] = rng.uniform(0.0, 0.3)     # parent PID age
            X[i, t, 46] = rng.beta(2.0, 2.0)        # event density in window
            X[i, t, 47] = rng.beta(1.0, 4.0)        # anomalous process chain score

        if is_malicious:
            # Pick attack pattern
            attack = rng.choice(list(ATTACK_PATTERNS.keys()))
            pattern = ATTACK_PATTERNS[attack]
            duration = min(pattern["duration"], seq_len // 4)
            burst_start = rng.randint(0, seq_len - duration)

            # Inject attack sequence
            for t in range(burst_start, burst_start + duration):
                # Anomalous event types dominate during attack window
                for ev_name in pattern["events"]:
                    ev_id = EVENT_TYPES[ev_name]
                    X[i, t, ev_id] = rng.uniform(0.8, 1.0)

                # Switch process category to attacker tooling
                for cat_name in pattern["proc_cats"]:
                    cat_id = PROC_CATEGORY_MAP[cat_name]["idx"] - 25
                    X[i, t, cat_id] = rng.uniform(0.7, 1.0)

                # Elevate privilege during attack
                X[i, t, 34] = rng.uniform(0.7, 1.0)

                # Anomalous time features during attack
                X[i, t, 36] = rng.uniform(0.2, 0.4) if "net_dns" in pattern["events"] else rng.uniform(0.6, 1.0)
                X[i, t, 42] = rng.uniform(0.5, 1.0)  # high subprocess count
                X[i, t, 47] = rng.uniform(0.6, 1.0)  # anomalous process chain

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
