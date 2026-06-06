"""LOLBAS feature profile adapter.

Parses LOLBAS YAML definitions of 237+ LOLBins and generates 64-dim feature
profiles for realistic training of the LOLBin detector model.

Each profile encodes:
  - Abuse categories present (Execute, Download, AWL Bypass, ADS, etc.)
  - MITRE ATT&CK technique mappings
  - Required privilege level
  - Command complexity / count
  - OS platform support breadth
  - Tags and detection coverage
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

LOLBIN_FEATURE_DIM = 64

LOLBAS_CATEGORIES = {
    "OSBinaries": 0,
    "OSLibraries": 1,
    "OSScripts": 2,
    "OtherMSBinaries": 3,
    "HonorableMentions": 4,
}

COMMAND_CATEGORIES = [
    "Execute",
    "Download",
    "AWL Bypass",
    "ADS",
    "Copy",
    "Read",
    "Compile",
    "Decode",
    "Encode",
    "Upload",
    "Persistence",
    "Privesc",
    "Evasion",
    "Recon",
    "ProcessInject",
    "Dump",
]

MITRE_MAPPING = {
    "T1059": 0,
    "T1218": 1,
    "T1105": 2,
    "T1564": 3,
    "T1127": 4,
    "T1055": 5,
    "T1003": 6,
    "T1047": 7,
    "T1134": 8,
    "T1546": 9,
    "T1547": 10,
    "T1553": 11,
    "T1562": 12,
    "T1574": 13,
    "T1053": 14,
    "T1204": 15,
    "T1197": 16,
    "T1110": 17,
    "T1016": 18,
    "T1036": 19,
}

logger = logging.getLogger(__name__)


def _load_privilege_vector(privileges: str) -> np.ndarray:
    priv = privileges.lower() if privileges else "user"
    vec = np.zeros(4, dtype=np.float32)
    if "admin" in priv or "administrator" in priv:
        vec[1] = 1.0
    elif "system" in priv:
        vec[2] = 1.0
    else:
        vec[0] = 1.0
    return vec


def _load_os_vector(os_list: list[str]) -> np.ndarray:
    vec = np.zeros(6, dtype=np.float32)
    for os_str in os_list:
        os_lower = os_str.lower()
        if "vista" in os_lower:
            vec[0] = 1.0
        if "7" in os_lower:
            vec[1] = 1.0
        if "8" in os_lower and "8.1" not in os_lower:
            vec[2] = 1.0
        if "8.1" in os_lower:
            vec[3] = 1.0
        if "10" in os_lower:
            vec[4] = 1.0
        if "11" in os_lower:
            vec[5] = 1.0
    return vec


def _load_mitre_vector(mitre_ids: list[str]) -> np.ndarray:
    vec = np.zeros(len(MITRE_MAPPING) + 8, dtype=np.float32)
    for mid in mitre_ids:
        mid_clean = mid.strip().upper()
        for prefix, idx_base in [("T1", 0), ("T2", 2), ("T3", 4), ("T4", 6)]:
            if mid_clean.startswith(prefix):
                break
        base_id = mid_clean[1:]
        for tech_id, idx in MITRE_MAPPING.items():
            if tech_id == mid_clean:
                vec[idx] = 1.0
    return vec


def parse_yaml_file(yaml_path: Path, category: str) -> dict[str, Any] | None:
    with open(yaml_path) as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.warning("Failed to parse %s: %s", yaml_path, e)
            return None
    if not data or not isinstance(data, dict):
        return None

    name = data.get("Name", yaml_path.stem)
    commands = data.get("Commands", [])
    if not commands:
        commands = []

    full_paths = data.get("Full_Path", [])
    detection = data.get("Detection", [])

    command_cats = set()
    mitre_ids = set()
    privileges = set()
    os_support = set()
    tags = set()

    for cmd in commands:
        if isinstance(cmd, dict):
            cat = cmd.get("Category")
            if cat:
                command_cats.add(cat)
            mid = cmd.get("MitreID")
            if mid:
                mitre_ids.add(mid)
            priv = cmd.get("Privileges")
            if priv:
                privileges.add(priv)
            os_str = cmd.get("OperatingSystem", "")
            if os_str:
                for part in os_str.split(","):
                    os_support.add(part.strip())
            tag_list = cmd.get("Tags", [])
            if isinstance(tag_list, list):
                for t in tag_list:
                    if isinstance(t, dict):
                        tags.update(t.values())
                    elif isinstance(t, str):
                        tags.add(t)

    if "IOC" in str(detection):
        tags.add("IOC")
    if "Sigma" in str(detection):
        tags.add("Sigma")
    if "Splunk" in str(detection):
        tags.add("Splunk")

    return {
        "name": name,
        "category_type": category,
        "command_categories": list(command_cats),
        "mitre_ids": list(mitre_ids),
        "privileges": list(privileges),
        "os_support": list(os_support),
        "tags": list(tags),
        "command_count": len(commands),
        "path_count": len(full_paths) if isinstance(full_paths, list) else 0,
    }


def build_feature_profile(entry: dict[str, Any]) -> np.ndarray:
    profile = np.zeros(LOLBIN_FEATURE_DIM, dtype=np.float32)

    # Feature 0-3: Binary category type (one-hot)
    category_idx = LOLBAS_CATEGORIES.get(entry["category_type"], 4)
    profile[category_idx] = 1.0

    # Feature 4-19: Command category flags
    for i, cmd_cat in enumerate(COMMAND_CATEGORIES):
        if cmd_cat in entry["command_categories"]:
            profile[4 + i] = 1.0

    # Feature 20-23: Privilege level
    priv = entry.get("privileges", ["User"])
    priv_str = priv[0] if priv else "User"
    priv_str_lower = priv_str.lower()
    if "admin" in priv_str_lower or "administrator" in priv_str_lower:
        profile[20] = 0.0
        profile[21] = 1.0
        profile[22] = 0.0
    elif "system" in priv_str_lower:
        profile[20] = 0.0
        profile[21] = 0.0
        profile[22] = 1.0
    else:
        profile[20] = 1.0
        profile[21] = 0.0
        profile[22] = 0.0
    profile[23] = 1.0 if len(entry.get("privileges", [])) > 1 else 0.0

    # Feature 24-29: OS support breadth
    os_vec = _load_os_vector(entry.get("os_support", []))
    profile[24:30] = os_vec

    # Feature 30: Command count (normalized)
    profile[30] = min(entry.get("command_count", 0) / 20.0, 1.0)

    # Feature 31: Path count (normalized)
    profile[31] = min(entry.get("path_count", 0) / 10.0, 1.0)

    # Feature 32-59: MITRE technique encoding (28 dims)
    mitre_vec = _load_mitre_vector(entry.get("mitre_ids", []))
    profile[32:60] = mitre_vec[:28]

    # Feature 60-61: Detection coverage
    tags = entry.get("tags", [])
    sigma_count = sum(1 for t in tags if t and "sigma" in t.lower())
    splunk_count = sum(1 for t in tags if t and "splunk" in t.lower())
    ioc_count = sum(1 for t in tags if t and "ioc" in t.lower())
    profile[60] = min((sigma_count + splunk_count) / 10.0, 1.0)
    profile[61] = min(ioc_count / 5.0, 1.0)

    # Feature 62: Category breadth (number of unique command categories)
    profile[62] = min(len(entry.get("command_categories", [])) / 8.0, 1.0)

    # Feature 63: Is well-known (has detection rules beyond basic)
    profile[63] = 1.0 if sigma_count + splunk_count + ioc_count > 0 else 0.0

    return profile


def load(
    config: dict[str, Any] | None = None,
) -> tuple[np.ndarray, np.ndarray, list[dict[str, Any]]]:
    config = config or {}
    base = Path(__file__).resolve().parent.parent.parent
    lolbas_path = Path(config.get("lolbas_path", base / "datasets/lolbas/LOLBAS-master"))
    n_malicious = config.get("n_malicious", 0)

    profiles = []
    entries = []

    for category in LOLBAS_CATEGORIES:
        yml_dir = lolbas_path / "yml" / category
        if not yml_dir.exists():
            logger.warning("LOLBAS category dir not found: %s", yml_dir)
            continue
        for yml_file in sorted(yml_dir.glob("*.yml")):
            entry = parse_yaml_file(yml_file, category)
            if entry:
                profile = build_feature_profile(entry)
                profiles.append(profile)
                entries.append(entry)

    X = np.array(profiles, dtype=np.float32)
    y = np.ones(len(X), dtype=np.float32)

    logger.info(
        "Loaded %d LOLBAS profiles (%d dimensions)",
        len(X),
        LOLBIN_FEATURE_DIM,
    )
    return X, y, entries


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )
    X, y, entries = load()
    print(f"Profiles: {X.shape}, malicious: {int(y.sum())}")
    cats = {}
    for e in entries:
        for cc in e["command_categories"]:
            cats[cc] = cats.get(cc, 0) + 1
    print(f"Command categories: {cats}")
