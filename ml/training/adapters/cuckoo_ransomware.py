#!/usr/bin/env python3
"""Extract 10-dim ransomware features from Cuckoo sandbox reports."""
import json, os, sys
from pathlib import Path
import numpy as np

RANSOM_FEATURES = [
    "entropy_increase_rate", "file_rename_rate", "file_delete_rate",
    "file_type_change_rate", "known_extension_append", "ransom_note_similarity",
    "shadow_copy_deletion", "encryption_api_calls", "network_beacon_rate",
    "unique_file_extensions",
]

# Known ransom note filenames (lowercase)
RANSOM_NOTES = {
    "readme.txt", "readme.html", "readme_now.txt", "how_to_decrypt.txt",
    "how_to_decrypt.html", "decrypt_info.txt", "decrypt_instructions.txt",
    "ransom_note.txt", "ransom_note.html", "recover.txt", "recover.html",
    "help_decrypt.txt", "help_decrypt.html", "#_README_#.txt",
    "files.txt", "restore.txt", "encrypted.txt", "lock.txt",
    "warning.txt", "info.hta", "info.txt", "instruction.txt",
    "how_to_back_files.txt", "how_to_decrypt_files.txt",
    "decrypt_files.txt", "all_files_are_encrypted.txt",
    "readme_decrypt.txt", "recovery.txt", "recovery_key.txt",
}

# Crypto API patterns
CRYPTO_APIS = {
    "cryptencrypt", "cryptdecrypt", "cryptacquirecontexta", "cryptacquirecontextw",
    "cryptgenkey", "cryptderivekey", "cryptdestroykey",
    "bcryptencrypt", "bcryptdecrypt", "bcryptgeneratekey",
    "ncryptencrypt", "ncryptdecrypt",
    "cryptprotectdata", "cryptunprotectdata",
    "cryptcreatehash", "crypthashdata", "cryptgethashparam",
    "rsaencrypt", "rsadecrypt",
    "cryptsetkeyparam", "cryptgetkeyparam",
    "cryptexportkey", "cryptimportkey",
}

def extract_features(report: dict) -> np.ndarray:
    feats = np.zeros(10, dtype=np.float32)
    behavior = report.get("behavior", {})
    summary = behavior.get("summary", {})
    sigs = [s.get("name", "").lower() for s in report.get("signatures", [])]
    network = report.get("network", {})
    procs = behavior.get("processes", [])

    f_created = set(summary.get("file_created", []))
    f_written = set(summary.get("file_written", []))
    f_deleted = set(summary.get("file_deleted", []))
    f_read = set(summary.get("file_read", []))
    f_opened = set(summary.get("file_opened", []))

    all_file_ops = f_created | f_written | f_deleted | f_read | f_opened
    base_names = set(os.path.basename(f).lower() for f in all_file_ops)
    exts = set()
    for f in all_file_ops:
        ext = os.path.splitext(f)[1].lower()
        if ext:
            exts.add(ext)

    total_files = len(all_file_ops)
    n_created = len(f_created)
    n_deleted = len(f_deleted)
    n_written = len(f_written)

    # 0: entropy_increase_rate = file manipulation intensity
    if total_files > 0:
        feats[0] = min((n_created + n_written) / max(total_files, 1), 1.0)
    # Higher means more file operations overall
    feats[0] = min(feats[0] + min(total_files / 500.0, 0.3), 1.0)

    # 1: file_rename_rate = created + deleted overlap suggests rename
    overlap = f_created & f_deleted
    if f_created or f_deleted:
        feats[1] = min(len(overlap) / max(len(f_created | f_deleted), 1) * 2.0, 1.0)

    # 2: file_delete_rate
    if total_files > 0:
        feats[2] = min(n_deleted / max(total_files, 1) * 3.0, 1.0)

    # 3: file_type_change_rate = diverse extensions per total files
    if total_files > 0 and exts:
        feats[3] = min(len(exts) / max(total_files, 1) * 5.0, 1.0)

    # 4: known_extension_append = ransomware-specific extensions
    rans_exts = {".encrypted", ".enc", ".locked", ".crypted", ".crypt", ".crypto",
                 ".encrypt", ".lock", ".ecc", ".ezz", ".exx", ".abc", ".aaa",
                 ".xyz", ".vvv", ".micro", ".cerber", ".cbi", ".cbr", ".cbk",
                 ".cbf", ".cba", ".cbb", ".cbc", ".cbd", ".cbe"}
    known_rans = exts & rans_exts
    feats[4] = min(len(known_rans) * 0.3, 1.0)

    # 5: ransom_note_similarity
    note_matches = sum(1 for b in base_names if b in RANSOM_NOTES)
    has_ransom_sig = any("ransom" in s for s in sigs)
    if note_matches > 0:
        feats[5] = min(0.5 + note_matches * 0.25, 1.0)
    elif has_ransom_sig:
        feats[5] = 0.6
    else:
        feats[5] = 0.0

    # 6: shadow_copy_deletion
    has_vssadmin = any("vssadmin" in s or "shadow" in s for s in sigs)
    has_wmi_delete = any("wmi" in p.get("process_name","").lower()
                         for p in procs[:5])
    for p in procs:
        pname = p.get("process_name", "").lower()
        if "vss" in pname or "shadow" in pname:
            has_vssadmin = True
    # Check API calls for shadow copy
    for p in procs:
        for c in p.get("calls", []):
            api = c.get("api", "").lower()
            if "vss" in api or "shadow" in api:
                has_vssadmin = True
                break
    feats[6] = 0.8 if has_vssadmin else 0.0

    # 7: encryption_api_calls
    crypto_count = 0
    for p in procs:
        for c in p.get("calls", []):
            api = c.get("api", "").lower()
            if api in CRYPTO_APIS:
                crypto_count += 1
    if crypto_count > 0:
        feats[7] = min(crypto_count / 20.0, 1.0)

    # 8: network_beacon_rate
    http = len(network.get("http", []))
    dns = len(network.get("dns", []))
    tcp = len(network.get("tcp", []))
    total_net = http + dns + tcp
    if total_net > 0:
        feats[8] = min(total_net / 100.0, 1.0)

    # 9: unique_file_extensions
    feats[9] = min(len(exts) / 30.0, 1.0)

    return feats.astype(np.float32)


def load_cuckoo_ransomware(max_samples: int = 500) -> tuple:
    cuckoo_base = "/tmp/cuckoo_extract"
    virus_dir = os.path.join(cuckoo_base, "CuckooVirusShare")
    clean_dir = os.path.join(cuckoo_base, "CuckooClean")

    X_list, y_list = [], []

    # Malware samples (from VirusShare)
    mal_dirs = sorted([d for d in os.listdir(virus_dir) if d.isdigit()], key=int)
    np.random.RandomState(42).shuffle(mal_dirs)
    for d in mal_dirs[:max_samples // 2]:
        fpath = os.path.join(virus_dir, d, "reports", "report.json")
        if not os.path.exists(fpath): continue
        with open(fpath) as f:
            report = json.load(f)
        score = report.get("info", {}).get("score", 0)
        if score < 1.0: continue  # skip very low-score samples
        feats = extract_features(report)
        X_list.append(feats)
        y_list.append(1)

    # Benign samples (from Clean)
    clean_dirs = sorted([d for d in os.listdir(clean_dir) if d.isdigit()], key=int)
    np.random.RandomState(42).shuffle(clean_dirs)
    for d in clean_dirs[:max_samples // 2]:
        fpath = os.path.join(clean_dir, d, "reports", "report.json")
        if not os.path.exists(fpath): continue
        with open(fpath) as f:
            report = json.load(f)
        score = report.get("info", {}).get("score", 0)
        if score > 2.0: continue  # skip high-score clean samples (shouldn't happen)
        feats = extract_features(report)
        X_list.append(feats)
        y_list.append(0)

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)
    return X, y, f"Cuckoo sandbox ({len(y)} samples: {int(y.sum())} mal, {int((y==0).sum())} ben)"
