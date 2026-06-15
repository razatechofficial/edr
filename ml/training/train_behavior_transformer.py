#!/usr/bin/env python3
"""Behavioral Transformer model — trained on real BETH data + synthetic augmentation.

Layout matches utils/features.py BehavioralFeatureEncoder:
  [0-24]  event subtype (25 one-hot)
  [25-32] process category (8 one-hot)
  [33-35] privilege level (3 one-hot: low, medium, high)
  [36-38] flags: network, file_write, registry
  [39]    time_of_day (0-1)
  [40-46] day_of_week (7 one-hot, Sunday=0)
  [47]    parent_score (0-1)
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils.features import EVENT_SUBTYPE_INDEX, PROCESS_CATEGORY_INDEX

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
        h = self.input_proj(x)
        h = self.pos_enc(h)
        h = self.encoder(h)
        pooled = h.mean(dim=1)
        return self.classifier(pooled)


# ── Augmented synthetic data (matches BETH feature distributions) ────────

EVENT_NAMES = list(EVENT_SUBTYPE_INDEX.keys())
EVENT_IDS = [EVENT_SUBTYPE_INDEX[k] for k in EVENT_NAMES]
CAT_NAMES = list(PROCESS_CATEGORY_INDEX.keys())
CAT_IDS = [PROCESS_CATEGORY_INDEX[k] for k in CAT_NAMES]

# Benign event probabilities (heuristic, matching BETH-like distributions)
EVENT_PROBS = np.array([
    0.12, 0.08, 0.002, 0.10, 0.10, 0.03, 0.02, 0.08,        # 0-7
    0.06, 0.02, 0.04, 0.04, 0.05, 0.02, 0.04, 0.01,         # 8-15
    0.03, 0.01, 0.005, 0.02, 0.01, 0.005, 0.04, 0.01, 0.002, # 16-24
], dtype=np.float64)
EVENT_PROBS /= EVENT_PROBS.sum()

CAT_PROBS = np.array([0.25, 0.15, 0.10, 0.15, 0.12, 0.05, 0.03, 0.15], dtype=np.float64)
CAT_PROBS /= CAT_PROBS.sum()


def generate_synthetic_data(n_samples: int = 10000, seq_len: int = 50,
                            seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    X = np.zeros((n_samples, seq_len, FEATURES_PER_EVENT), dtype=np.float32)
    y = np.zeros(n_samples, dtype=np.float32)

    for i in range(n_samples):
        is_malicious = rng.random() < 0.25

        for t in range(seq_len):
            ev_id = rng.choice(EVENT_IDS, p=EVENT_PROBS)
            X[i, t, ev_id] = 1.0

            cat_id = rng.choice(CAT_IDS, p=CAT_PROBS)
            X[i, t, 25 + cat_id] = 1.0

            # Privilege: mostly low, ~15% medium (system services)
            if rng.random() < 0.85:
                X[i, t, 33] = 1.0
            else:
                X[i, t, 34] = 1.0

            # Flags based on event type
            ev_name = EVENT_NAMES[ev_id]
            X[i, t, 36] = float(ev_name.startswith("network_"))
            X[i, t, 37] = float(ev_name == "file_write")
            X[i, t, 38] = float(ev_name.startswith("registry_"))

            # Time
            X[i, t, 39] = rng.uniform(0.0, 1.0)
            dow = rng.randint(0, 7)
            X[i, t, 40 + dow] = 1.0

            # Parent score: mostly low for benign
            X[i, t, 47] = rng.beta(2.0, 5.0)

        if is_malicious:
            attack_type = rng.choice([
                "network_beacon", "data_exfil", "ransomware", "recon"
            ])
            duration = rng.randint(15, 40)
            burst_start = rng.randint(0, seq_len - duration)

            for t in range(burst_start, burst_start + duration):
                if attack_type == "network_beacon":
                    X[i, t, 8] = rng.uniform(0.8, 1.0)       # network_connect
                    X[i, t, 36] = rng.uniform(0.8, 1.0)       # net_flag
                    X[i, t, 10] = rng.uniform(0.7, 1.0)       # network_send
                    X[i, t, 12] = rng.uniform(0.6, 1.0)       # network_dns
                    X[i, t, 25 + 7] = rng.uniform(0.7, 1.0)   # cat_unknown

                elif attack_type == "data_exfil":
                    X[i, t, 8] = rng.uniform(0.8, 1.0)
                    X[i, t, 10] = rng.uniform(0.8, 1.0)
                    X[i, t, 12] = rng.uniform(0.7, 1.0)
                    X[i, t, 36] = rng.uniform(0.8, 1.0)
                    X[i, t, 25 + 7] = rng.uniform(0.7, 1.0)

                elif attack_type == "ransomware":
                    X[i, t, 4] = rng.uniform(0.8, 1.0)        # file_write
                    X[i, t, 6] = rng.uniform(0.8, 1.0)        # file_rename
                    X[i, t, 5] = rng.uniform(0.8, 1.0)        # file_delete
                    X[i, t, 37] = rng.uniform(0.8, 1.0)       # filew_flag
                    X[i, t, 25 + 7] = rng.uniform(0.7, 1.0)

                elif attack_type == "recon":
                    X[i, t, 12] = rng.uniform(0.8, 1.0)       # network_dns
                    X[i, t, 8] = rng.uniform(0.7, 1.0)        # network_connect
                    X[i, t, 36] = rng.uniform(0.7, 1.0)
                    X[i, t, 25 + 7] = rng.uniform(0.7, 1.0)

                # Malicious processes use low privilege (realistic)
                X[i, t, 33] = rng.uniform(0.7, 1.0)
                X[i, t, 34] = rng.uniform(0.0, 0.1)
                X[i, t, 35] = 0.0

                # Slightly elevated parent score
                X[i, t, 47] = rng.uniform(0.4, 0.7)

                # Suppress system category
                X[i, t, 25 + 0] = 0.0

            y[i] = 1.0

    return X, y


# ── Training ─────────────────────────────────────────────────────────────

def train(args: argparse.Namespace) -> None:
    device = torch.device("cpu")
    log.info("Training behavioral transformer on %s", device)

    datasets = []

    # 1. Real BETH training data
    beth_path = Path(args.beth_dir) / "training_sequences.npz"
    if beth_path.exists() and args.use_beth:
        data = np.load(str(beth_path))
        X_beth = data["X"].astype(np.float32)
        y_beth = data["y"].astype(np.float32)
        log.info("Loaded BETH training: %d samples (%.1f%% malicious)",
                 len(y_beth), y_beth.mean() * 100)
        datasets.append((X_beth, y_beth, "BETH"))

    # 2. Synthetic data
    if args.n_synthetic > 0:
        X_syn, y_syn = generate_synthetic_data(args.n_synthetic, args.seq_len)
        log.info("Generated synthetic: %d samples (%.1f%% malicious)",
                 len(y_syn), y_syn.mean() * 100)
        datasets.append((X_syn, y_syn, "synthetic"))

    if not datasets:
        log.error("No training data available")
        return

    X_list, y_list = zip(*[(X, y) for X, y, _ in datasets])
    X_np = np.vstack(X_list).astype(np.float32)
    y_np = np.concatenate(y_list).astype(np.float32)

    shuffle = np.random.RandomState(42).permutation(len(y_np))
    X_np, y_np = X_np[shuffle], y_np[shuffle]

    split = int(len(X_np) * 0.8)
    X_train = torch.from_numpy(X_np[:split]).to(device)
    y_train = torch.from_numpy(y_np[:split]).unsqueeze(1).to(device)
    X_test = torch.from_numpy(X_np[split:]).to(device)
    y_test = torch.from_numpy(y_np[split:]).unsqueeze(1).to(device)

    log.info("Training: %d | Validation: %d (%.1f%% malicious)",
             len(X_train), len(X_test), y_np[split:].mean() * 100)

    model = BehaviorTransformer(
        input_dim=FEATURES_PER_EVENT,
        d_model=args.d_model,
        nhead=args.nhead,
        num_layers=args.num_layers,
        max_seq=args.seq_len,
    ).to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-5)
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

        if (epoch + 1) % 5 == 0:
            log.info("Epoch %d/%d  val_loss=%.4f  acc=%.4f  best=%.4f",
                     epoch + 1, args.epochs, val_loss, acc, best_loss)

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    onnx_path = output / "behavior_transformer.onnx"

    model.eval()
    dummy = torch.randn(1, args.seq_len, FEATURES_PER_EVENT).to(device)
    torch.onnx.export(
        model, dummy, onnx_path,
        input_names=["input"],
        output_names=["score"],
        dynamic_axes={"input": {0: "batch", 1: "seq_len"},
                      "score": {0: "batch"}},
        opset_version=15,
    )
    log.info("Exported -> %s (%d bytes)", onnx_path, onnx_path.stat().st_size)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output-dir", default="./output")
    p.add_argument("--epochs", type=int, default=30)
    p.add_argument("--batch-size", type=int, default=64)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--d-model", type=int, default=DEFAULT_D_MODEL)
    p.add_argument("--nhead", type=int, default=DEFAULT_NHEAD)
    p.add_argument("--num-layers", type=int, default=DEFAULT_NUM_LAYERS)
    p.add_argument("--seq-len", type=int, default=50)
    p.add_argument("--n-synthetic", type=int, default=10000)
    p.add_argument("--use-beth", action="store_true", default=True)
    p.add_argument("--beth-dir", default="ml/datasets/beth")
    train(p.parse_args())


if __name__ == "__main__":
    main()
