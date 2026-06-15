#!/usr/bin/env python3
"""Extract 64-dim LOLBin features from Cuckoo sandbox reports (process-level)."""
import json, os, re
from pathlib import Path
import numpy as np

FEATURE_DIM = 64

SUSP_FLAGS = [
    "-enc", "-encodedcommand", "-nop", "-noprofile",
    "-w hidden", "-windowstyle hidden", "-bypass", "-exec bypass",
    "-noninteractive", "downloadstring", "downloadfile",
    "invoke-expression", "iex", "frombase64string",
    "new-object", "net.webclient", "bitstransfer",
    "start-process", "invoke-webrequest",
]

KNOWN_LOLBINS = {
    "mshta.exe": 0.9, "mshta": 0.9,
    "wscript.exe": 0.8, "wscript": 0.8,
    "cscript.exe": 0.8, "cscript": 0.8,
    "regsvr32.exe": 0.8, "regsvr32": 0.8,
    "installutil.exe": 0.8, "installutil": 0.8,
    "powershell.exe": 0.7, "powershell": 0.7,
    "pwsh.exe": 0.7, "pwsh": 0.7,
    "rundll32.exe": 0.7, "rundll32": 0.7,
    "certutil.exe": 0.7, "certutil": 0.7,
    "wmic.exe": 0.7, "wmic": 0.7,
    "bitsadmin.exe": 0.7, "bitsadmin": 0.7,
    "msiexec.exe": 0.6, "msiexec": 0.6,
    "schtasks.exe": 0.5, "schtasks": 0.5,
    "at.exe": 0.5, "at": 0.5,
    "cmd.exe": 0.4, "cmd": 0.4,
}

SCRIPT_INTERPS = {"powershell", "pwsh", "wscript", "cscript", "mshta", "python", "perl", "ruby"}

B64_PATTERN = re.compile(r'[A-Za-z0-9+/=]{41,}')

def count_base64_runs(cmdline: str) -> float:
    matches = B64_PATTERN.findall(cmdline)
    total = sum(len(m) for m in matches)
    return min(total / 100.0, 1.0)

def extract_lolbin_features(processes: list) -> list[tuple[np.ndarray, str]]:
    pid_map = {}
    for p in processes:
        pid_map[p.get("pid")] = p

    results = []
    for p in processes:
        feats = np.zeros(FEATURE_DIM, dtype=np.float32)
        pname = (p.get("process_name") or "").lower().strip()
        cmdline = (p.get("command_line") or "").lower()
        ppid = p.get("ppid")

        # [0:19] Suspicious CLI flags
        for i, flag in enumerate(SUSP_FLAGS):
            if flag in cmdline:
                feats[i] = 1.0

        # [19] Base64 run score
        feats[19] = count_base64_runs(cmdline)

        # [20] Ancestor depth + [21] Process risk + [22] Parent risk + [23:30] Ancestor risks
        name_lookup = KNOWN_LOLBINS.get(pname, None)
        for try_name in [pname, pname + ".exe", pname.replace(".exe", "")]:
            if try_name in KNOWN_LOLBINS:
                name_lookup = KNOWN_LOLBINS[try_name]
                break

        ancestors = []
        cur = p
        for _ in range(10):
            parent_pid = cur.get("ppid")
            if parent_pid is None or parent_pid == cur.get("pid"):
                break
            parent = pid_map.get(parent_pid)
            if parent is None or parent.get("process_name") == pname:
                break
            ancestors.append(parent)
            cur = parent

        feats[20] = min(len(ancestors) / 10.0, 1.0)

        if name_lookup is not None:
            feats[21] = name_lookup
        else:
            feats[21] = 0.0

        if ancestors:
            parent_name = ancestors[0].get("process_name", "").lower()
            p_risk = KNOWN_LOLBINS.get(parent_name, 0.0)
            if p_risk == 0.0:
                p_risk = KNOWN_LOLBINS.get(parent_name + ".exe", 0.0)
            feats[22] = p_risk

            for j, anc in enumerate(ancestors[:8]):
                anc_name = anc.get("process_name", "").lower()
                a_risk = KNOWN_LOLBINS.get(anc_name, 0.0)
                if a_risk == 0.0:
                    a_risk = KNOWN_LOLBINS.get(anc_name + ".exe", 0.0)
                feats[23 + j] = a_risk

        # [32] Child count
        child_count = sum(1 for other in processes if other.get("ppid") == p.get("pid"))
        feats[32] = min(child_count / 20.0, 1.0)

        # [40] Is script interpreter
        base_name = pname.replace(".exe", "")
        feats[40] = 1.0 if base_name in SCRIPT_INTERPS else 0.0

        # [41] Pipe count
        pipe_count = cmdline.count("|")
        feats[41] = min(pipe_count / 5.0, 1.0)

        # [48] Registry ops — skip API call parsing for speed (set to 0)
        feats[48] = 0.0

        results.append((feats, pname))

    return results


def load_cuckoo_lolbin(max_samples: int = 1000):
    cuckoo_base = "/tmp/cuckoo_extract"
    virus_dir = os.path.join(cuckoo_base, "CuckooVirusShare")
    clean_dir = os.path.join(cuckoo_base, "CuckooClean")

    X_list, y_list = [], []
    rng = np.random.RandomState(42)

    mal_dirs = sorted([d for d in os.listdir(virus_dir) if d.isdigit()], key=int)
    rng.shuffle(mal_dirs)
    for d in mal_dirs:
        if len(X_list) >= max_samples: break
        fpath = os.path.join(virus_dir, d, "reports", "report.json")
        if not os.path.exists(fpath): continue
        with open(fpath) as f:
            report = json.load(f)
        procs = report.get("behavior", {}).get("processes", [])
        results = extract_lolbin_features(procs)
        for feats, pname in results:
            if len(X_list) >= max_samples: break
            X_list.append(feats)
            y_list.append(1)

    clean_dirs = sorted([d for d in os.listdir(clean_dir) if d.isdigit()], key=int)
    rng.shuffle(clean_dirs)
    for d in clean_dirs:
        if len(X_list) >= max_samples * 2: break
        fpath = os.path.join(clean_dir, d, "reports", "report.json")
        if not os.path.exists(fpath): continue
        with open(fpath) as f:
            report = json.load(f)
        procs = report.get("behavior", {}).get("processes", [])
        results = extract_lolbin_features(procs)
        for feats, pname in results:
            if len(X_list) >= max_samples * 2: break
            X_list.append(feats)
            y_list.append(0)

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)
    perm = rng.permutation(len(y))
    return X[perm], y[perm], f"Cuckoo process-level ({len(y)} samples)"
