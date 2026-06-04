#!/usr/bin/env python3
"""Memory injection detector using memory forensics features.

Detects process injection techniques including RWX region allocation, PE
headers in non-module memory, high-entropy executable regions, and unbacked
memory mappings. Trained on CIC-MalMem-2022 dataset plus synthetic data.

Features (32-dim):
  - Malfind (0-3): injection count, commit charge, protection, unique sites
  - psxview (4-7): hidden process indicators across scan methods
  - ldrmodules (8-11): DLL detachment indicators
  - Handle stats (12-15): cross-process handle types
  - Process stats (16-19): 64-bit ratio, thread/handle counts
  - Kernel anomalies (20-23): callbacks, drivers, hidden services
  - False avg (24-27): volatility false negative averages
  - Risk composites (28-31): aggregated injection risk scores
"""

from __future__ import annotations

import argparse
import logging
import zipfile
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("train_memory_injection")

MEMORY_INJECTION_FEATURE_DIM = 32


class MemoryInjectionDetector(nn.Module):
    def __init__(self, input_dim: int = MEMORY_INJECTION_FEATURE_DIM):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


# ---------------------------------------------------------------------------
# CIC-MalMem-2022 dataset loader
# ---------------------------------------------------------------------------

MALMEM_COLUMNS = [
    "pslist.nproc", "pslist.nppid", "pslist.avg_threads", "pslist.nprocs64bit",
    "pslist.avg_handlers", "dlllist.ndlls", "dlllist.avg_dlls_per_proc",
    "handles.nhandles", "handles.avg_handles_per_proc", "handles.nport",
    "handles.nfile", "handles.nevent", "handles.ndesktop", "handles.nkey",
    "handles.nthread", "handles.ndirectory", "handles.nsemaphore",
    "handles.ntimer", "handles.nsection", "handles.nmutant",
    "ldrmodules.not_in_load", "ldrmodules.not_in_init", "ldrmodules.not_in_mem",
    "ldrmodules.not_in_load_avg", "ldrmodules.not_in_init_avg", "ldrmodules.not_in_mem_avg",
    "malfind.ninjections", "malfind.commitCharge", "malfind.protection",
    "malfind.uniqueInjections",
    "psxview.not_in_pslist", "psxview.not_in_eprocess_pool",
    "psxview.not_in_ethread_pool", "psxview.not_in_pspcid_list",
    "psxview.not_in_csrss_handles", "psxview.not_in_session",
    "psxview.not_in_deskthrd",
    "psxview.not_in_pslist_false_avg", "psxview.not_in_eprocess_pool_false_avg",
    "psxview.not_in_ethread_pool_false_avg", "psxview.not_in_pspcid_list_false_avg",
    "psxview.not_in_csrss_handles_false_avg", "psxview.not_in_session_false_avg",
    "psxview.not_in_deskthrd_false_avg",
    "modules.nmodules", "svcscan.nservices", "svcscan.kernel_drivers",
    "svcscan.fs_drivers", "svcscan.process_services",
    "svcscan.shared_process_services", "svcscan.interactive_process_services",
    "svcscan.nactive", "callbacks.ncallbacks", "callbacks.nanonymous",
    "callbacks.ngeneric",
]


def _raw_to_features(row: dict[str, float]) -> np.ndarray:
    feats = np.zeros(MEMORY_INJECTION_FEATURE_DIM, dtype=np.float32)

    total_procs = max(row.get("pslist.nproc", 1), 1)

    # [0-3]: Malfind indicators
    feats[0] = np.clip(row.get("malfind.ninjections", 0) / total_procs, 0, 1)
    feats[1] = np.clip(row.get("malfind.commitCharge", 0) / 100.0, 0, 1)
    feats[2] = np.clip(row.get("malfind.protection", 0) / 100.0, 0, 1)
    feats[3] = np.clip(row.get("malfind.uniqueInjections", 0) / 10.0, 0, 1)

    # [4-7]: psxview hidden processes
    psx_fields = [
        "psxview.not_in_pslist", "psxview.not_in_eprocess_pool",
        "psxview.not_in_ethread_pool", "psxview.not_in_pspcid_list",
        "psxview.not_in_csrss_handles", "psxview.not_in_session",
        "psxview.not_in_deskthrd",
    ]
    psx_total = sum(row.get(f, 0) for f in psx_fields) + 1
    feats[4] = np.clip(row.get("psxview.not_in_pslist", 0) / psx_total, 0, 1)
    feats[5] = np.clip(row.get("psxview.not_in_eprocess_pool", 0) / psx_total, 0, 1)
    feats[6] = np.clip(row.get("psxview.not_in_csrss_handles", 0) / psx_total, 0, 1)
    composite = sum(row.get(f, 0) for f in psx_fields) / max(len(psx_fields), 1)
    feats[7] = np.clip(composite / 10.0, 0, 1)

    # [8-11]: ldrmodule anomalies
    feats[8] = np.clip(row.get("ldrmodules.not_in_load_avg", 0), 0, 1)
    feats[9] = np.clip(row.get("ldrmodules.not_in_init_avg", 0), 0, 1)
    feats[10] = np.clip(row.get("ldrmodules.not_in_mem_avg", 0), 0, 1)
    ldr_avg = (feats[8] + feats[9] + feats[10]) / 2.0
    feats[11] = np.clip(ldr_avg, 0, 1)

    # [12-15]: Handle stats
    total_handles = max(row.get("handles.nhandles", 1), 1)
    feats[12] = np.clip(row.get("handles.nport", 0) / total_handles * 5.0, 0, 1)
    feats[13] = np.clip(row.get("handles.nthread", 0) / total_handles * 5.0, 0, 1)
    feats[14] = np.clip(row.get("handles.nsection", 0) / total_handles * 5.0, 0, 1)
    handle_types = sum(1 for k in row if k.startswith("handles.") and k != "handles.nhandles" and k != "handles.avg_handles_per_proc")
    feats[15] = np.clip(handle_types / 20.0, 0, 1)

    # [16-19]: Process stats
    feats[16] = np.clip(row.get("pslist.nprocs64bit", 0) / 50.0, 0, 1)
    feats[17] = np.clip(row.get("pslist.avg_threads", 0) / 30.0, 0, 1)
    feats[18] = np.clip(row.get("pslist.avg_handlers", 0) / 500.0, 0, 1)
    feats[19] = np.clip(row.get("pslist.nppid", 0) / 30.0, 0, 1)

    # [20-23]: Kernel/service anomalies
    feats[20] = np.clip(row.get("callbacks.ncallbacks", 0) / 100.0, 0, 1)
    total_cb = row.get("callbacks.ncallbacks", 1)
    feats[21] = np.clip(row.get("callbacks.nanonymous", 0) / max(total_cb, 1), 0, 1)
    total_svc = max(row.get("svcscan.nservices", 1), 1)
    feats[22] = row.get("svcscan.kernel_drivers", 0) / total_svc
    feats[23] = 0.0

    # [24-27]: psxview false averages
    feats[24] = np.clip(row.get("psxview.not_in_pslist_false_avg", 0), 0, 1)
    feats[25] = np.clip(row.get("psxview.not_in_eprocess_pool_false_avg", 0), 0, 1)
    feats[26] = np.clip(row.get("psxview.not_in_csrss_handles_false_avg", 0), 0, 1)
    feats[27] = np.clip(row.get("psxview.not_in_deskthrd_false_avg", 0), 0, 1)

    # [28-31]: Composite risk scores
    feats[28] = np.clip(feats[0] * feats[1] * 10.0 + feats[2] * feats[3] * 5.0, 0, 1)
    feats[29] = np.clip(feats[4] + feats[5] + feats[6] + feats[7], 0, 1)
    feats[30] = np.clip(feats[8] + feats[9] + feats[10] + feats[11], 0, 1)
    feats[31] = np.clip((feats[28] * 0.4 + feats[29] * 0.3 + feats[30] * 0.3) * 2.0, 0, 1)

    return feats


def load_malmem_dataset(zip_path: str) -> tuple[np.ndarray, np.ndarray]:
    """Load CIC-MalMem-2022 from the bundled zip and map to 32-dim features."""
    import csv

    log.info("Loading CIC-MalMem-2022 from %s ...", zip_path)
    X_list: list[np.ndarray] = []
    y_list: list[int] = []

    with zipfile.ZipFile(zip_path) as z:
        csv_name = [n for n in z.namelist() if n.endswith(".csv")][0]
        with z.open(csv_name) as f:
            text = f.read().decode("utf-8", errors="replace")
            reader = csv.DictReader(text.splitlines())
            for row in reader:
                cls = row.get("Class", "").strip()
                if cls.lower() == "malware":
                    label = 1
                else:
                    label = 0

                parsed = {}
                for col in MALMEM_COLUMNS:
                    val = row.get(col, "0")
                    try:
                        parsed[col] = float(val) if val else 0.0
                    except ValueError:
                        parsed[col] = 0.0

                feats = _raw_to_features(parsed)
                X_list.append(feats)
                y_list.append(label)

    X = np.stack(X_list)
    y = np.array(y_list, dtype=np.int32)
    shuffle = np.random.RandomState(42).permutation(len(y))
    X, y = X[shuffle], y[shuffle]
    log.info("Loaded %d samples (%d mal / %d ben)", len(y), int(y.sum()), int((y == 0).sum()))
    return X, y


# ---------------------------------------------------------------------------
# Synthetic injection technique generators
# Each generates feature profiles for a specific injection type.
# ---------------------------------------------------------------------------

INJECTION_TECHNIQUES = {
    "shellcode_rwx": {
        "desc": "PEzor/Metasploit shellcode — RWX allocation, encrypted payload, high entropy",
        "profile": {
            0: (0.3, 0.6), 1: (0.5, 0.9), 2: (0.6, 1.0), 3: (0.3, 0.7),
            4: (0.1, 0.3), 5: (0.0, 0.1), 6: (0.3, 0.5), 7: (0.2, 0.4),
            8: (0.1, 0.3), 9: (0.1, 0.3), 10: (0.1, 0.3), 11: (0.1, 0.3),
            12: (0.1, 0.4), 13: (0.3, 0.7), 14: (0.3, 0.6), 15: (0.3, 0.6),
            16: (0.1, 0.3), 17: (0.3, 0.7), 18: (0.3, 0.7), 19: (0.2, 0.5),
            20: (0.1, 0.3), 21: (0.1, 0.3), 22: (0.1, 0.3), 23: (0.1, 0.3),
            24: (0.1, 0.3), 25: (0.1, 0.3), 26: (0.1, 0.3), 27: (0.1, 0.3),
        },
    },
    "process_hollowing": {
        "desc": "RunPE hollowing — suspended process, image unmapped, SetThreadContext",
        "profile": {
            0: (0.4, 0.8), 1: (0.3, 0.7), 2: (0.5, 0.9), 3: (0.4, 0.8),
            4: (0.3, 0.7), 5: (0.1, 0.4), 6: (0.3, 0.6), 7: (0.4, 0.8),
            8: (0.4, 0.8), 9: (0.3, 0.7), 10: (0.4, 0.8), 11: (0.4, 0.8),
            12: (0.3, 0.6), 13: (0.4, 0.8), 14: (0.3, 0.7), 15: (0.4, 0.7),
            16: (0.3, 0.6), 17: (0.5, 0.9), 18: (0.5, 0.9), 19: (0.5, 0.9),
            20: (0.2, 0.5), 21: (0.1, 0.3), 22: (0.2, 0.4), 23: (0.1, 0.3),
            24: (0.2, 0.5), 25: (0.2, 0.5), 26: (0.2, 0.5), 27: (0.2, 0.5),
        },
    },
    "reflective_dll": {
        "desc": "Reflective DLL load — manual mapping, no loader, section anomalies",
        "profile": {
            0: (0.4, 0.9), 1: (0.3, 0.7), 2: (0.5, 0.9), 3: (0.5, 0.9),
            4: (0.2, 0.5), 5: (0.1, 0.3), 6: (0.3, 0.6), 7: (0.3, 0.6),
            8: (0.5, 0.9), 9: (0.5, 0.9), 10: (0.5, 0.9), 11: (0.5, 0.9),
            12: (0.2, 0.5), 13: (0.3, 0.6), 14: (0.4, 0.7), 15: (0.4, 0.7),
            16: (0.2, 0.4), 17: (0.3, 0.6), 18: (0.4, 0.7), 19: (0.3, 0.6),
            20: (0.2, 0.4), 21: (0.1, 0.3), 22: (0.3, 0.5), 23: (0.2, 0.4),
            24: (0.2, 0.4), 25: (0.2, 0.4), 26: (0.2, 0.4), 27: (0.2, 0.4),
        },
    },
    "ptrace_linux": {
        "desc": "Linux ptrace injection — attach, PTRACE_POKEDATA, register hijack",
        "profile": {
            0: (0.2, 0.5), 1: (0.1, 0.4), 2: (0.3, 0.6), 3: (0.2, 0.5),
            4: (0.2, 0.5), 5: (0.1, 0.4), 6: (0.2, 0.5), 7: (0.3, 0.6),
            8: (0.2, 0.4), 9: (0.2, 0.4), 10: (0.2, 0.4), 11: (0.2, 0.4),
            12: (0.4, 0.8), 13: (0.5, 0.9), 14: (0.2, 0.5), 15: (0.5, 0.8),
            16: (0.1, 0.3), 17: (0.4, 0.7), 18: (0.3, 0.6), 19: (0.4, 0.7),
            20: (0.3, 0.6), 21: (0.2, 0.5), 22: (0.2, 0.4), 23: (0.2, 0.4),
            24: (0.2, 0.5), 25: (0.2, 0.5), 26: (0.2, 0.5), 27: (0.2, 0.5),
        },
    },
    "dyld_macos": {
        "desc": "macOS DYLD injection — DYLD_INSERT_LIBRARIES, task_for_pid, mach_vm",
        "profile": {
            0: (0.2, 0.5), 1: (0.2, 0.5), 2: (0.3, 0.6), 3: (0.3, 0.6),
            4: (0.2, 0.5), 5: (0.1, 0.3), 6: (0.2, 0.4), 7: (0.3, 0.5),
            8: (0.3, 0.6), 9: (0.3, 0.6), 10: (0.3, 0.6), 11: (0.3, 0.6),
            12: (0.3, 0.6), 13: (0.4, 0.7), 14: (0.3, 0.7), 15: (0.4, 0.7),
            16: (0.2, 0.4), 17: (0.3, 0.6), 18: (0.4, 0.7), 19: (0.3, 0.6),
            20: (0.3, 0.6), 21: (0.2, 0.5), 22: (0.2, 0.4), 23: (0.2, 0.5),
            24: (0.2, 0.4), 25: (0.2, 0.4), 26: (0.2, 0.4), 27: (0.2, 0.4),
        },
    },
}


def _apply_injection_profile(
    X: np.ndarray, idx: list[int], profile: dict, rng: np.random.RandomState,
) -> None:
    for feat_idx, (lo, hi) in profile.items():
        X[np.ix_(idx, [feat_idx])] = rng.uniform(lo, hi, (len(idx), 1))


def generate_synthetic_injection_data(
    n_benign: int = 8000,
    n_per_technique: int = 2000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic memory injection data for multiple techniques.

    Covers shellcode RWX, process hollowing, reflective DLL, ptrace, and
    DYLD injection patterns — injection types not fully represented in
    the CIC-MalMem-2022 Volatility-based dataset.
    """
    rng = np.random.RandomState(seed)
    n_techniques = len(INJECTION_TECHNIQUES)
    n_mal = n_per_technique * n_techniques
    n = n_benign + n_mal

    X = rng.beta(2, 5, (n, MEMORY_INJECTION_FEATURE_DIM)).astype(np.float32)
    y = np.zeros(n, dtype=np.float32)

    offset = n_benign
    for tech_name, tech in INJECTION_TECHNIQUES.items():
        batch = list(range(offset, offset + n_per_technique))
        _apply_injection_profile(X, batch, tech["profile"], rng)

        for i in batch:
            X[i, 28] = np.clip(X[i, 0] * X[i, 1] * 10.0 + X[i, 2] * X[i, 3] * 5.0, 0, 1)
            X[i, 29] = np.clip(X[i, 4] + X[i, 5] + X[i, 6] + X[i, 7], 0, 1)
            X[i, 30] = np.clip(X[i, 8] + X[i, 9] + X[i, 10] + X[i, 11], 0, 1)
            X[i, 31] = np.clip((X[i, 28] * 0.4 + X[i, 29] * 0.3 + X[i, 30] * 0.3) * 2.0, 0, 1)
            y[i] = 1.0

        log.info("  %-25s %5d samples", tech_name, n_per_technique)
        offset += n_per_technique

    np.clip(X, 0.0, 1.0, out=X)
    return X, y


def generate_synthetic_data(n: int = 20000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Legacy generic synthetic data generator (kept for backward compat)."""
    rng = np.random.RandomState(seed)

    X = rng.beta(2, 5, (n, MEMORY_INJECTION_FEATURE_DIM)).astype(np.float32)
    y = np.zeros(n, dtype=np.float32)

    n_mal = int(n * 0.25)
    mal_idx = rng.choice(n, n_mal, replace=False)

    for i in mal_idx:
        for f in range(28):
            X[i, f] = rng.uniform(0.3, 0.9)
        y[i] = 1.0

    for i in mal_idx:
        X[i, 28] = np.clip(X[i, 0] * X[i, 1] * 10.0 + X[i, 2] * X[i, 3] * 5.0, 0, 1)
        X[i, 29] = np.clip(X[i, 4] + X[i, 5] + X[i, 6] + X[i, 7], 0, 1)
        X[i, 30] = np.clip(X[i, 8] + X[i, 9] + X[i, 10] + X[i, 11], 0, 1)
        X[i, 31] = np.clip((X[i, 28] * 0.4 + X[i, 29] * 0.3 + X[i, 30] * 0.3) * 2.0, 0, 1)

    np.clip(X, 0.0, 1.0, out=X)
    return X, y


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


def train(args: argparse.Namespace) -> None:
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    datasets_loaded = []

    if args.malmem_zip and Path(args.malmem_zip).exists():
        log.info("Loading CIC-MalMem-2022 dataset ...")
        X_mm, y_mm = load_malmem_dataset(args.malmem_zip)
        datasets_loaded.append((X_mm, y_mm, "CIC-MalMem-2022"))
    else:
        log.info("CIC-MalMem-2022 not found, skipping")

    if args.synthetic_injection > 0:
        log.info(
            "Generating synthetic injection data (%d benign + %d/technique) ...",
            args.n_benign, args.synthetic_injection,
        )
        X_syn, y_syn = generate_synthetic_injection_data(
            n_benign=args.n_benign,
            n_per_technique=args.synthetic_injection,
        )
        datasets_loaded.append((X_syn, y_syn, "synthetic_injection"))
    else:
        log.info("No synthetic injection data requested")

    if not datasets_loaded:
        log.info("No real data available, using generic synthetic data (%d samples)", args.n_samples)
        X_syn, y_syn = generate_synthetic_data(args.n_samples)
        datasets_loaded.append((X_syn, y_syn, "generic_synthetic"))

    X_list, y_list = zip(*[(X, y) for X, y, _ in datasets_loaded])
    X_np = np.vstack(X_list)
    y_np = np.concatenate(y_list)

    shuffle = np.random.RandomState(42).permutation(len(y_np))
    X_np, y_np = X_np[shuffle], y_np[shuffle]

    log.info("Combined dataset: %d samples (%.1f%% malicious)", len(y_np), y_np.mean() * 100)
    for X, y, name in datasets_loaded:
        log.info("  %-30s %5d samples (%.1f%% malicious)", name, len(y), y.mean() * 100)

    split = int(len(X_np) * 0.8)
    X_train = torch.from_numpy(X_np[:split])
    y_train = torch.from_numpy(y_np[:split]).unsqueeze(1).float()
    X_test = torch.from_numpy(X_np[split:])
    y_test = torch.from_numpy(y_np[split:]).unsqueeze(1).float()

    model = MemoryInjectionDetector()
    optimizer = torch.optim.AdamW(model.parameters(), lr=5e-3, weight_decay=1e-4)
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

    onnx_path = output / "memory_injection.onnx"
    model.eval()
    dummy = torch.randn(1, MEMORY_INJECTION_FEATURE_DIM)
    torch.onnx.export(
        model, dummy, str(onnx_path),
        input_names=["input"], output_names=["score"],
        dynamic_axes={"input": {0: "batch"}, "score": {0: "batch"}},
        opset_version=15,
    )
    log.info("Exported -> %s (%d bytes)", onnx_path, onnx_path.stat().st_size)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output-dir", default="./output")
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--n-samples", type=int, default=5000)
    p.add_argument("--n-benign", type=int, default=8000,
                   help="Benign samples for synthetic injection data")
    p.add_argument("--synthetic-injection", type=int, default=0,
                   help="Samples per injection technique (0 = skip)")
    p.add_argument("--malmem-zip", type=str, default=None,
                   help="Path to CIC-MalMem-2022.zip")
    train(p.parse_args())


if __name__ == "__main__":
    main()
