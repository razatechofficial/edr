"""LOLBin feature adapter using LOLBAS YAML + Atomic Red Team data.

Extracts 64-dim feature vectors from real LOLBin definitions and
Atomic Red Team test descriptions, then generates realistic training data.

Features (64-dim) matching Go runtime:
  - [0:18]  Command-line suspicious flags
  - [19]    Base64 character run score
  - [20]    Ancestor count / 10
  - [21]    Process name LOLBin risk score
  - [22]    Parent process name LOLBin risk score
  - [23:30] Ancestor LOLBin risk scores (up to 8)
  - [31]    Unused
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

import logging
import os
import re
from pathlib import Path
from typing import Any

import numpy as np
import yaml

log = logging.getLogger("lolbin_adapter")

LOLBIN_FEATURE_DIM = 64

SUSP_FLAGS = [
    "-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden",
    "-windowstyle hidden", "-bypass", "-exec bypass", "-noninteractive",
    "downloadstring", "downloadfile", "invoke-expression", "iex",
    "frombase64string", "new-object", "net.webclient", "bitstransfer",
    "start-process", "invoke-webrequest",
]

KNOWN_LOLBINS = {
    "powershell.exe": 0.7, "pwsh.exe": 0.7, "cmd.exe": 0.4,
    "wscript.exe": 0.8, "cscript.exe": 0.8, "mshta.exe": 0.9,
    "regsvr32.exe": 0.8, "rundll32.exe": 0.7, "certutil.exe": 0.8,
    "msiexec.exe": 0.6, "installutil.exe": 0.8, "wmic.exe": 0.7,
    "bitsadmin.exe": 0.7, "schtasks.exe": 0.5, "at.exe": 0.5,
}

SCRIPT_INTERPRETERS = {"powershell", "pwsh", "wscript", "cscript", "mshta", "python", "perl", "ruby"}

IDX_BASE64 = 19
IDX_ANCESTOR_DEPTH = 20
IDX_PROC_RISK = 21
IDX_PARENT_RISK = 22
IDX_ANCESTOR_RISK_START = 23
IDX_CHILD_COUNT = 32
IDX_SCRIPT_INTERP = 40
IDX_PIPE_COUNT = 41
IDX_REG_OPS = 48


def parse_lolbas_yaml(yaml_path: str) -> dict[str, Any] | None:
    try:
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        log.warning("Cannot parse %s: %s", yaml_path, e)
        return None
    if not data:
        return None
    return {
        "name": data.get("Name", ""),
        "description": data.get("Description", ""),
        "category": data.get("Category", ""),
        "commands": data.get("Commands", []),
        "detection": data.get("Detection", {}),
    }


def find_lolbas_yamls(base_dir: str) -> list[dict[str, Any]]:
    entries = []
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            if f.endswith((".yml", ".yaml")) and f != "YML-Template.yml":
                full = os.path.join(root, f)
                entry = parse_lolbas_yaml(full)
                if entry:
                    entries.append(entry)
    return entries


def parse_atomic_yaml(yaml_path: str) -> dict[str, Any] | None:
    try:
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
    except Exception:
        return None
    if not data:
        return None
    
    # Extract test commands
    tests = []
    for test in data.get("atomic_tests", []):
        executor = test.get("executor", {})
        command = executor.get("command", "")
        if command:
            tests.append(command)
    
    return {
        "name": data.get("name", ""),
        "description": data.get("description", ""),
        "tests": tests,
        "tactic": data.get("attack_technique", ""),
    }


def find_atomic_yamls(base_dir: str) -> list[dict[str, Any]]:
    entries = []
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".yaml") and not f.endswith(".md"):
                full = os.path.join(root, f)
                entry = parse_atomic_yaml(full)
                if entry and entry["tests"]:
                    entries.append(entry)
    return entries


def compute_features_from_lolbas(lolbas_entry: dict[str, Any]) -> np.ndarray:
    x = np.zeros(LOLBIN_FEATURE_DIM, dtype=np.float32)
    name = lolbas_entry.get("name", "").lower()
    description = lolbas_entry.get("description", "").lower()
    commands = lolbas_entry.get("commands", [])
    category = lolbas_entry.get("category", "").lower()

    # Determine the binary name
    binary_name = Path(name).name if name else ""
    
    # Process risk score
    risk_score = KNOWN_LOLBINS.get(binary_name, 0.3)
    x[IDX_PROC_RISK] = risk_score
    
    # Script interpreter check
    for interp in SCRIPT_INTERPRETERS:
        if interp in binary_name:
            x[IDX_SCRIPT_INTERP] = 1.0
            break
    
    # Check description for LOLBin indicators
    if "download" in description:
        x[15] = 1.0  # downloadstring/downloadfile flag
    if "execute" in description or "run" in description:
        x[17] = 1.0  # start-process flag
    if "bypass" in description:
        x[6] = 1.0  # bypass flag
    if "base64" in description or "encode" in description:
        x[IDX_BASE64] = 0.6
    
    # Check commands for suspicious flags
    for cmd_entry in commands:
        cmd_text = ""
        if isinstance(cmd_entry, dict):
            cmd_text = cmd_entry.get("command", "")
            if isinstance(cmd_text, list):
                cmd_text = " ".join(str(c) for c in cmd_text)
        elif isinstance(cmd_entry, str):
            cmd_text = cmd_entry
        cmd_lower = str(cmd_text).lower()
        
        for i, flag in enumerate(SUSP_FLAGS):
            if flag in cmd_lower:
                x[i] = max(x[i], 0.8)
        
        # Base64 detection
        b64_patterns = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', cmd_text)
        if b64_patterns:
            x[IDX_BASE64] = max(x[IDX_BASE64], 0.8)
        
        # Registry operations
        if "reg" in cmd_lower or "registry" in cmd_lower:
            x[IDX_REG_OPS] = max(x[IDX_REG_OPS], 0.5)
        
        # Pipe detection
        if "|" in cmd_text:
            x[IDX_PIPE_COUNT] = min(1.0, x[IDX_PIPE_COUNT] + 0.3)
    
    # Add noise for realistic variation
    noise = np.random.default_rng().normal(0, 0.05, LOLBIN_FEATURE_DIM).astype(np.float32)
    x = np.clip(x + noise, 0.0, 1.0)
    
    return x


def compute_features_from_atomic(atomic_entry: dict[str, Any]) -> np.ndarray:
    x = np.zeros(LOLBIN_FEATURE_DIM, dtype=np.float32)
    name = atomic_entry.get("name", "").lower()
    tests = atomic_entry.get("tests", [])

    # Check if this is LOLBin-related
    lolbin_name = None
    for lb in KNOWN_LOLBINS:
        if lb.replace(".exe", "") in name or lb.split(".")[0] in name:
            lolbin_name = lb
            break
    
    if lolbin_name:
        x[IDX_PROC_RISK] = KNOWN_LOLBINS[lolbin_name]
        for interp in SCRIPT_INTERPRETERS:
            if interp in lolbin_name:
                x[IDX_SCRIPT_INTERP] = 1.0
                break
    
    for test in tests:
        cmd_lower = test.lower()
        
        for i, flag in enumerate(SUSP_FLAGS):
            if flag in cmd_lower:
                x[i] = max(x[i], 0.8)
        
        b64_patterns = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', test)
        if b64_patterns:
            x[IDX_BASE64] = max(x[IDX_BASE64], 0.8)
        
        if "|" in test:
            x[IDX_PIPE_COUNT] = min(1.0, x[IDX_PIPE_COUNT] + 0.3)
        
        if "reg" in cmd_lower:
            x[IDX_REG_OPS] = max(x[IDX_REG_OPS], 0.4)
        
        if "child" in cmd_lower or "spawn" in cmd_lower or "create" in cmd_lower:
            x[IDX_CHILD_COUNT] = max(x[IDX_CHILD_COUNT], 0.3)
    
    # Ancestor features (simulate realistic parent chains)
    if lolbin_name:
        x[IDX_ANCESTOR_DEPTH] = 0.5
        x[IDX_PARENT_RISK] = 0.3
        if x[IDX_PROC_RISK] > 0.7:
            x[IDX_ANCESTOR_RISK_START] = 0.6
    
    noise = np.random.default_rng().normal(0, 0.05, LOLBIN_FEATURE_DIM).astype(np.float32)
    x = np.clip(x + noise, 0.0, 1.0)
    
    return x


def generate_training_data(
    lolbas_dir: str | None = None,
    atomic_dir: str | None = None,
    n_benign: int = 30000,
    n_malicious: int = 10000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    
    if lolbas_dir is None:
        lolbas_dir = str(
            Path(__file__).parent.parent.parent / "datasets" / "lolbas" / "LOLBAS-master"
        )
    if atomic_dir is None:
        atomic_dir = str(
            Path(__file__).parent.parent.parent / "datasets" / "edr_datasets" / "atomic-red-team" / "atomics"
        )

    # Extract real LOLBin features
    real_mal_features = []
    
    lolbas_entries = find_lolbas_yamls(lolbas_dir)
    log.info("Found %d LOLBAS YAML entries", len(lolbas_entries))
    for entry in lolbas_entries:
        fv = compute_features_from_lolbas(entry)
        real_mal_features.append(fv)
    
    atomic_entries = find_atomic_yamls(atomic_dir)
    log.info("Found %d Atomic Red Team YAML entries with tests", len(atomic_entries))
    for entry in atomic_entries:
        fv = compute_features_from_atomic(entry)
        real_mal_features.append(fv)
    
    n_real_mal = len(real_mal_features)
    log.info("Total real LOLBin features extracted: %d", n_real_mal)
    
    X_benign = _gen_benign_batch(n_benign, rng)
    y_benign = np.zeros(n_benign, dtype=np.float32)
    
    if n_real_mal >= 100:
        X_mal = np.array(real_mal_features[:n_malicious], dtype=np.float32)
        n_use = min(len(X_mal), n_malicious)
        X_mal = X_mal[:n_use]
    else:
        # Use real features to parameterize generator
        X_mal = _gen_synthetic_malicious(n_malicious, real_mal_features, rng)
    
    X = np.concatenate([X_benign, X_mal], axis=0)
    y = np.concatenate([y_benign, np.ones(len(X_mal), dtype=np.float32)], axis=0)
    
    perm = rng.permutation(len(X))
    X, y = X[perm], y[perm]
    
    log.info("Training data: %d samples (%d benign, %d malicious)",
             len(X), n_benign, len(X_mal))
    return X, y


def _gen_benign_batch(n: int, rng: np.random.RandomState) -> np.ndarray:
    X = np.zeros((n, LOLBIN_FEATURE_DIM), dtype=np.float32)
    for i in range(n):
        x = np.zeros(LOLBIN_FEATURE_DIM, dtype=np.float32)
        x[:20] = rng.uniform(0.0, 0.05, size=20)
        x[20] = rng.uniform(0.0, 0.3)
        x[32] = rng.uniform(0.0, 0.3)
        x[48] = rng.uniform(0.0, 0.2)
        X[i] = x
    return X


def _gen_synthetic_malicious(
    n: int,
    real_features: list[np.ndarray],
    rng: np.random.RandomState,
) -> np.ndarray:
    X = np.zeros((n, LOLBIN_FEATURE_DIM), dtype=np.float32)
    
    if real_features:
        real_arr = np.array(real_features, dtype=np.float32)
        means = real_arr.mean(axis=0)
        stds = np.clip(real_arr.std(axis=0), 0.05, 0.3)
    else:
        means = np.zeros(LOLBIN_FEATURE_DIM)
        means[21] = 0.7  # proc risk
        means[40] = 0.5  # script interp
        stds = np.ones(LOLBIN_FEATURE_DIM) * 0.15
    
    for i in range(n):
        x = rng.normal(means, stds)
        x = np.clip(x, 0.0, 1.0)
        X[i] = x.astype(np.float32)
    
    return X


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    X, y = generate_training_data(n_benign=1000, n_malicious=500)
    print(f"X shape: {X.shape}, y shape: {y.shape}")
    print(f"Malicious: {int(y.sum())}, Benign: {int(len(y) - y.sum())}")
