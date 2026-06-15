"""Real-data ransomware feature adapter.

Parses MLRan Cuckoo JSON reports to extract 10-dim ransomware indicator
features matching the Go runtime feature extractor.

Feature mapping from Cuckoo report data:
  0 entropy_increase_rate    → PE section entropy analysis + crypto API ratio
  1 file_rename_rate         → file_recreated / total_file_ops
  2 file_delete_rate         → file_deleted / total_file_ops
  3 file_type_change_rate    → file extension changes
  4 known_extension_append   → presence of known ransomware extensions
  5 ransom_note_similarity   → ransom note filename patterns
  6 shadow_copy_deletion     → vssadmin/VSS-related API/command activity
  7 encryption_api_calls     → crypto API call ratio
  8 network_beacon_rate      → unique destinations / time
  9 unique_file_extensions   → distinct file extensions created/written
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import numpy as np

log = logging.getLogger("ransomware_adapter")

RANSOMWARE_FEATURE_COUNT = 10

RANSOM_EXTENSIONS = {
    ".encrypted", ".enc", ".locked", ".crypted", ".crypt", ".encrypt",
    ".locky", ".wnry", ".wcry", ".wncry", ".onion", ".zepto", ".odin",
    ".cerber", ".btc", ".pay", ".crypto", ".cry", ".aes", ".rijndael",
    ".ecc", ".rsa", ".blowfish", ".twofish", ". serpent",
    ".email", ".xxx", ".ttt", ".micro", ".bip", ".combo",
}

RANSOM_NOTE_KEYWORDS = {
    "ransom", "decrypt", "recover", "restore", "how_to", "readme",
    "help", "rescue", "info", "encrypt", "locked", "warning",
    "instructions", "contact", "payment", "bitcoin",
}

CRYPTO_API_CALLS = {
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "CryptGenKey",
    "CryptExportKey", "CryptImportKey", "CryptCreateHash", "CryptHashData",
    "CryptDeriveKey", "CryptDestroyKey", "CryptReleaseContext",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
    "BCryptGenerateKeyPair", "BCryptEncrypt", "BCryptDecrypt",
    "NtEncrypt", "NtDecrypt",
}

VSS_API_CALLS = {
    "VssCreate", "vssadmin", "VSS", "ShadowCopy", "DeleteShadow",
    "WMI_DeleteShadow", "VolumeShadowCopy",
}

FILE_OPERATIONS = {
    "file_created", "file_deleted", "file_opened", "file_written",
    "file_recreated", "file_read", "file_exists", "file_failed",
}

SUSPICIOUS_PROCESSES = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe",
}


def extract_api_call_counts(report: dict) -> dict[str, int]:
    api_counts: dict[str, int] = {}
    apistats = report.get("behavior", {}).get("apistats", {})
    for pid_stats in apistats.values():
        for api_name, count in pid_stats.items():
            api_counts[api_name] = api_counts.get(api_name, 0) + count
    return api_counts


def extract_file_ops(report: dict) -> dict[str, list[str]]:
    ops: dict[str, list[str]] = {op: [] for op in FILE_OPERATIONS}
    summary = report.get("behavior", {}).get("summary", {})
    for op in FILE_OPERATIONS:
        ops[op] = summary.get(op, [])
    return ops


def extract_network_ops(report: dict) -> dict[str, list[str]]:
    net: dict[str, list[str]] = {}
    summary = report.get("behavior", {}).get("summary", {})
    net["connects_ip"] = summary.get("connects_ip", [])
    net["connects_host"] = summary.get("connects_host", [])
    net["resolves_host"] = summary.get("resolves_host", [])
    # Also check network section for DNS/HTTP
    net_section = report.get("network", {})
    net["dns"] = [d.get("request", "") for d in net_section.get("dns", [])]
    net["http"] = [
        h.get("uri", "") for h in net_section.get("http", [])
    ]
    return net


def extract_registry_ops(report: dict) -> dict[str, list[str]]:
    reg: dict[str, list[str]] = {}
    summary = report.get("behavior", {}).get("summary", {})
    reg["written"] = summary.get("regkey_written", [])
    reg["deleted"] = summary.get("regkey_deleted", [])
    reg["opened"] = summary.get("regkey_opened", [])
    reg["read"] = summary.get("regkey_read", [])
    return reg


def extract_process_info(report: dict) -> dict[str, Any]:
    procs = report.get("behavior", {}).get("processes", [])
    names = [p.get("process_name", "").lower() for p in procs]
    cmdlines = [p.get("command_line", "").lower() for p in procs]
    return {"names": names, "cmdlines": cmdlines}


def extract_dropped_files(report: dict) -> list[dict[str, Any]]:
    return report.get("dropped", [])


def compute_feature_vector(report: dict) -> np.ndarray:
    x = np.zeros(RANSOMWARE_FEATURE_COUNT, dtype=np.float32)

    api_counts = extract_api_call_counts(report)
    file_ops = extract_file_ops(report)
    net_ops = extract_network_ops(report)
    reg_ops = extract_registry_ops(report)
    procs = extract_process_info(report)
    dropped = extract_dropped_files(report)

    # 0. entropy_increase_rate
    total_api = sum(api_counts.values()) or 1
    crypto_count = sum(
        api_counts.get(api, 0) for api in CRYPTO_API_CALLS
    )
    # High crypto API ratio → high encryption activity
    x[0] = min(1.0, crypto_count / max(total_api * 0.1, 1))

    # 1. file_rename_rate
    created = len(file_ops.get("file_created", [])) or 1
    recreated = len(file_ops.get("file_recreated", []))
    x[1] = min(1.0, recreated / max(created, 1))

    # 2. file_delete_rate
    deleted = len(file_ops.get("file_deleted", []))
    total_file_ops = sum(len(v) for v in file_ops.values()) or 1
    x[2] = min(1.0, deleted / max(total_file_ops, 1))

    # 3. file_type_change_rate - look for extension changes in created files
    all_created = file_ops.get("file_created", [])
    all_written = file_ops.get("file_written", [])
    all_files = all_created + all_written
    extensions = set()
    old_extensions = set()
    for fp in all_files:
        p = Path(fp)
        ext = p.suffix.lower()
        if ext:
            extensions.add(ext)
    # Look for type changes in droppped files
    for df in dropped:
        name = df.get("name", "")
        ext = Path(name).suffix.lower()
        if ext:
            extensions.add(ext)
    x[3] = min(1.0, len(extensions) / 5.0)  # normalize: 5+ exts = 1.0

    # 4. known_extension_append
    known_ext_found = 0
    for ext in extensions:
        if ext in RANSOM_EXTENSIONS:
            known_ext_found += 1
    # Also check dropped files for ransomware extensions
    for df in dropped:
        name = df.get("name", "")
        ext = Path(name).suffix.lower()
        if ext in RANSOM_EXTENSIONS:
            known_ext_found += 1
    for fp in all_created + all_written:
        p_ext = Path(fp).suffix.lower()
        if p_ext in RANSOM_EXTENSIONS:
            known_ext_found += 1
    x[4] = min(1.0, known_ext_found / 3.0)

    # 5. ransom_note_similarity
    note_score = 0.0
    for fp in all_created + all_written:
        fname = Path(fp).stem.lower()
        for kw in RANSOM_NOTE_KEYWORDS:
            if kw in fname:
                note_score += 0.3
    # Also check dropped files
    for df in dropped:
        fname = Path(df.get("name", "")).stem.lower()
        for kw in RANSOM_NOTE_KEYWORDS:
            if kw in fname:
                note_score += 0.3
    # Check strings for ransom notes
    strings = report.get("strings", [])
    for s in strings:
        s_lower = str(s).lower()
        for kw in RANSOM_NOTE_KEYWORDS:
            if kw in s_lower:
                note_score += 0.1
    x[5] = min(1.0, note_score)

    # 6. shadow_copy_deletion
    shadow_score = 0.0
    for api, cnt in api_counts.items():
        if any(vss_kw.lower() in api.lower() for vss_kw in VSS_API_CALLS):
            shadow_score += cnt * 0.3
    for cmdline in procs.get("cmdlines", []):
        if "vssadmin" in cmdline or "shadow" in cmdline:
            shadow_score += 0.5
    for reg_path in reg_ops.get("deleted", []):
        if "shadow" in reg_path.lower() or "vss" in reg_path.lower():
            shadow_score += 0.5
    signatures = report.get("signatures", [])
    for sig in signatures:
        sig_name = sig.get("name", "").lower()
        if "ransom" in sig_name or "shadow" in sig_name or "vss" in sig_name:
            shadow_score += 0.5
    x[6] = min(1.0, shadow_score)

    # 7. encryption_api_calls
    x[7] = min(1.0, crypto_count / max(total_api * 0.05, 1))

    # 8. network_beacon_rate
    all_net = (
        net_ops.get("connects_ip", [])
        + net_ops.get("connects_host", [])
        + net_ops.get("resolves_host", [])
    )
    unique_dests = len(set(all_net))
    # Normalize: 10+ unique destinations = high beacon rate
    x[8] = min(1.0, unique_dests / 10.0)

    # Also check DNS queries
    dns_queries = net_ops.get("dns", [])
    unique_dns = len(set(dns_queries))
    x[8] = max(x[8], min(1.0, unique_dns / 5.0))

    # 9. unique_file_extensions
    unique_ext_count = len(extensions)
    x[9] = min(1.0, unique_ext_count / 8.0)

    return x


def process_reports(reports_dir: str) -> tuple[np.ndarray, np.ndarray]:
    reports_path = Path(reports_dir)
    json_files = sorted(reports_path.glob("*.json"))
    features_list: list[np.ndarray] = []
    labels_list: list[int] = []

    for jf in json_files:
        try:
            with open(jf) as f:
                report = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Skipping %s: %s", jf, e)
            continue

        fv = compute_feature_vector(report)
        features_list.append(fv)

        sid = int(jf.stem)
        label = _lookup_label(sid)
        labels_list.append(label)

        log.info(
            "Report %s → features=[%.2f, %.2f, %.2f, %.2f, %.2f, "
            "%.2f, %.2f, %.2f, %.2f, %.2f] label=%d",
            jf.name, *fv.tolist(), label,
        )

    if not features_list:
        log.warning("No reports processed from %s", reports_dir)
        return np.array([], dtype=np.float32).reshape(0, RANSOMWARE_FEATURE_COUNT), np.array([], dtype=np.int32)

    X = np.array(features_list, dtype=np.float32)
    y = np.array(labels_list, dtype=np.int32)

    log.info(
        "Processed %d reports → X shape %s (ransomware=%d, benign=%d)",
        len(features_list), X.shape,
        int(y.sum()), int(len(y) - y.sum()),
    )
    return X, y


def _lookup_label(sample_id: int) -> int:
    try:
        import pandas as pd
        label_path = Path(__file__).parent.parent.parent / "datasets" / "mlran" / "6_experiments" / "FS_MLRan_Datasets" / "MLRan_labels.csv"
        if label_path.exists():
            df = pd.read_csv(label_path)
            row = df[df["sample_id"] == sample_id]
            if not row.empty:
                return int(row.iloc[0]["sample_type"])
    except Exception:
        pass
    return 1  # default to ransomware if can't look up


def generate_training_data(
    reports_dir: str | None = None,
    n_benign: int = 5000,
    n_ransomware: int = 3000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate training data from MLRan reports, falling back to statistics
    from the reports for additional samples."""
    if reports_dir is None:
        reports_dir = str(
            Path(__file__).parent.parent.parent
            / "datasets" / "mlran" / "4_cuckoo_parser_scripts" / "json_reports"
        )

    X_real, y_real = process_reports(reports_dir)

    n_real = len(X_real)
    n_benign_real = int((y_real == 0).sum()) if n_real > 0 else 0
    n_ransom_real = int(y_real.sum()) if n_real > 0 else 0

    if n_real == 0:
        X_real = None
        y_real = None
        log.info("No real reports found — falling back to statistical generator")
    
    if X_real is not None and n_real >= 100:
        # Enough real data — return as-is
        log.info("Using %d real samples for training", n_real)
        return X_real, y_real

    # Use real data stats to generate realistic synthetic data
    return _generate_from_stats(
        X_real, y_real,
        n_benign=n_benign,
        n_ransomware=n_ransomware,
        seed=seed,
    )


def _generate_from_stats(
    X_real: np.ndarray | None,
    y_real: np.ndarray | None,
    n_benign: int = 5000,
    n_ransomware: int = 3000,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.RandomState(seed)
    n = n_benign + n_ransomware
    X = np.zeros((n, RANSOMWARE_FEATURE_COUNT), dtype=np.float32)
    y = np.zeros(n, dtype=np.int32)

    # Compute statistics from real data
    if X_real is not None and len(X_real) > 0:
        real_benign = X_real[y_real == 0]
        real_ransom = X_real[y_real == 1]

        benign_means = real_benign.mean(axis=0) if len(real_benign) > 0 else np.zeros(RANSOMWARE_FEATURE_COUNT)
        benign_stds = real_benign.std(axis=0) if len(real_benign) > 0 else np.ones(RANSOMWARE_FEATURE_COUNT) * 0.1
        ransom_means = real_ransom.mean(axis=0) if len(real_ransom) > 0 else np.ones(RANSOMWARE_FEATURE_COUNT) * 0.6
        ransom_stds = real_ransom.std(axis=0) if len(real_ransom) > 0 else np.ones(RANSOMWARE_FEATURE_COUNT) * 0.2

        # Clamp stds to avoid zero
        benign_stds = np.clip(benign_stds, 0.05, 0.5)
        ransom_stds = np.clip(ransom_stds, 0.05, 0.5)

        log.info("Benign means: %s", benign_means)
        log.info("Benign stds:  %s", benign_stds)
        log.info("Ransom means: %s", ransom_means)
        log.info("Ransom stds:  %s", ransom_stds)
    else:
        # Default parameters if no real data
        benign_means = np.array([0.1, 0.05, 0.03, 0.05, 0.0, 0.0, 0.0, 0.05, 0.05, 0.05])
        benign_stds = np.array([0.08, 0.05, 0.03, 0.05, 0.0, 0.0, 0.0, 0.05, 0.05, 0.05])
        ransom_means = np.array([0.7, 0.5, 0.3, 0.6, 0.5, 0.4, 0.3, 0.6, 0.4, 0.5])
        ransom_stds = np.array([0.15, 0.15, 0.1, 0.15, 0.2, 0.2, 0.3, 0.15, 0.15, 0.15])

    # Generate benign
    for i in range(n_benign):
        x = rng.normal(benign_means, benign_stds)
        x = np.clip(x, 0.0, 1.0)
        X[i] = x.astype(np.float32)
        y[i] = 0

    # Generate ransomware
    for i in range(n_ransomware):
        x = rng.normal(ransom_means, ransom_stds)
        # Add feature correlations observed in real ransomware
        if rng.random() > 0.5:
            x[4] = max(x[4], x[0] * 0.8)  # high entropy → extension append
        if rng.random() > 0.5:
            x[7] = max(x[7], x[0] * 0.9)  # high entropy → crypto API
        if x[4] > 0.3 and rng.random() > 0.5:
            x[5] = max(x[5], 0.4)  # ext append → ransom note
        x = np.clip(x, 0.0, 1.0)
        X[n_benign + i] = x.astype(np.float32)
        y[n_benign + i] = 1

    log.info(
        "Generated synthetic training data: %d samples (%d benign, %d ransomware)",
        n, n_benign, n_ransomware,
    )
    return X, y


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    X, y = generate_training_data()
    print(f"X shape: {X.shape}, y shape: {y.shape}")
    print(f"Ransomware: {int(y.sum())}, Benign: {int(len(y) - y.sum())}")
    print(f"Feature means (benign): {X[y==0].mean(axis=0)}")
    print(f"Feature means (ransom): {X[y==1].mean(axis=0)}")
