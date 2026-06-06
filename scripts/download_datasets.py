#!/usr/bin/env python3
"""Comprehensive dataset downloader for EDR ML model training.

Downloads public security datasets to supplement synthetic-only training
data for production-grade models.

Usage:
    python scripts/download_datasets.py                    # All sources
    python scripts/download_datasets.py --model network     # Network model only
    python scripts/download_datasets.py --dry-run           # Show URLs only
"""

from __future__ import annotations

import argparse
import gzip
import logging
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Callable

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
)
log = logging.getLogger("download_datasets")

DATASETS_DIR = Path(__file__).resolve().parent.parent / "ml" / "datasets"
CHUNK_SIZE = 32 * 1024 * 1024  # 32 MB
TIMEOUT = 900  # 15 min


# ---------------------------------------------------------------------------
# Source definitions
# ---------------------------------------------------------------------------

SourceDef = tuple[
    str,                    # name
    str,                    # url or (callable, param) for custom fetcher
    str | Callable,         # output path or custom download function
    str,                    # size hint
    str,                    # description
    list[str],              # models this dataset applies to
    bool,                   # extract (True/False)
]

SOURCES: list[SourceDef] = [
    # -- CIC-IDS2017 (Network Anomaly) --
    *[
        (
            f"cic2017_{day}",
            f"https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/{fname}",
            f"cic-ids2017/csv/{fname}",
            f"{size_mb}MB",
            f"CIC-IDS2017: {desc}",
            ["network"],
            False,  # no extraction needed (raw CSV)
        )
        for day, fname, size_mb, desc in [
            ("monday", "Monday-WorkingHours.pcap_ISCX.csv", 177, "Monday normal"),
            ("tuesday", "Tuesday-WorkingHours.pcap_ISCX.csv", 135, "Tuesday brute force + FTP"),
            ("wednesday", "Wednesday-workingHours.pcap_ISCX.csv", 225, "Wednesday DoS + DDoS"),
            ("thu_morning", "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", 52, "Thursday web attacks"),
            ("thu_afternoon", "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", 83, "Thursday infiltration"),
            ("fri_morning", "Friday-WorkingHours-Morning.pcap_ISCX.csv", 58, "Friday normal + botnet"),
            ("fri_ddos", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", 77, "Friday DDoS"),
            ("fri_portscan", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", 77, "Friday port scan"),
        ]
    ],
    # -- LOLBAS (LOLBin Detector) --
    (
        "lolbas",
        "https://github.com/LOLBAS-Project/LOLBAS/archive/refs/heads/master.zip",
        "lolbas/LOLBAS-master.zip",
        "5MB",
        "LOLBAS: LOLBin YAML definitions for living-off-the-land binaries",
        ["lolbin"],
        True,
    ),
    # -- MITRE ATT&CK (All models) --
    (
        "mitre_attack",
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "mitre/enterprise-attack.json",
        "15MB",
        "MITRE ATT&CK Enterprise: techniques, sub-techniques, mitigations",
        ["pe", "network", "behavior", "ransomware", "lolbin", "supply_chain", "aigen", "identity", "memory_injection"],
        False,
    ),
    # -- BETH dataset (Behavioral / Anomaly Detection) --
    (
        "beth_dataset",
        "https://data.hpc.imperial.ac.uk/resolve/?doi=9422&file=4&access=",
        "beth/full_BETH_dataset.zip",
        "41MB",
        "BETH: Behavioral Malware Dataset for Windows process behavior (8M datapoints, 23 hosts)",
        ["behavior", "ransomware"],
        True,
    ),
    (
        "beth_training",
        "https://data.hpc.imperial.ac.uk/resolve/?doi=9422&file=1&access=",
        "beth/labelled_training_data.csv",
        "197MB",
        "BETH: Labelled training data (labeled behavioral traces)",
        ["behavior", "ransomware"],
        False,
    ),
    # -- MalDICT (Behavioral + PE) --
    (
        "maldict",
        "https://github.com/rjjoyce/MalDICT/archive/refs/heads/main.zip",
        "maldict/MalDICT-main.zip",
        "300MB",
        "MalDICT: malware tagged by behavior, platform, vulnerability, packer (40M VirusTotal reports)",
        ["pe", "behavior", "ransomware"],
        True,
    ),
    # -- Stratosphere CTU-13 (Network) --
    (
        "ctu13",
        "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2",
        "stratosphere-ips/CTU-13-Dataset.tar.bz2",
        "2GB",
        "CTU-13: 13 malware capture scenarios with botnet, normal, background traffic",
        ["network"],
        True,
    ),
    # -- CIC-IDS2018 (Network Anomaly) -- requires AWS CLI (aws s3 sync)
    (
        "cic2018_fri0203",
        "https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
        "cic-ids2018/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
        "336MB",
        "CIC-IDS2018: Friday March 2 botnet traffic",
        ["network"],
        False,
    ),
    (
        "cic2018_fri1602",
        "https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
        "cic-ids2018/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
        "318MB",
        "CIC-IDS2018: Friday Feb 16 DoS GoldenEye+Slowloris",
        ["network"],
        False,
    ),
    (
        "cic2018_fri2302",
        "https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
        "cic-ids2018/Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
        "365MB",
        "CIC-IDS2018: Friday Feb 23 infiltration+botnet",
        ["network"],
        False,
    ),
    (
        "cic2018_tue2002",
        "https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
        "cic-ids2018/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
        "3.9GB",
        "CIC-IDS2018: Tuesday Feb 20 DoS Slowhttptest+Hulk",
        ["network"],
        False,
    ),
    (
        "cic2018_thu0103",
        "https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
        "cic-ids2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
        "103MB",
        "CIC-IDS2018: Thursday March 1 infiltration",
        ["network"],
        False,
    ),
    (
        "cic2018_thu1502",
        "https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
        "cic-ids2018/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
        "359MB",
        "CIC-IDS2018: Thursday Feb 15 FTP+SSH brute force",
        ["network"],
        False,
    ),
    (
        "cic2018_thu2202",
        "https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
        "cic-ids2018/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
        "365MB",
        "CIC-IDS2018: Thursday Feb 22 DDoS LOIC-UDP",
        ["network"],
        False,
    ),
    (
        "cic2018_wed1402",
        "https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        "cic-ids2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        "342MB",
        "CIC-IDS2018: Wednesday Feb 14 benign baseline",
        ["network"],
        False,
    ),
    (
        "cic2018_wed2102",
        "https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
        "cic-ids2018/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
        "314MB",
        "CIC-IDS2018: Wednesday Feb 21 DDoS LOIC-HTTP+HOIC",
        ["network"],
        False,
    ),
    (
        "cic2018_wed2802",
        "https://cse-cic-ids2018.s3.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
        "cic-ids2018/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
        "200MB",
        "CIC-IDS2018: Wednesday Feb 28 web attacks BF+XSS+SQLi",
        ["network"],
        False,
    ),
]

# ---------------------------------------------------------------------------
# Custom downloaders for datasets needing special handling
# ---------------------------------------------------------------------------

def _download_cic2022_malmem(dest: Path) -> bool:
    """CIC-MalMem-2022 is already downloaded; just verify."""
    existing = dest.parent / "cic-malmem-2022.zip"
    if not existing.exists():
        # Try alternate path
        alt = DATASETS_DIR / "edr_datasets" / "cic-malmem-2022.zip"
        if alt.exists():
            log.info("  Found at alternate path: %s", alt)
            return True
        log.info("  Already present in edr_datasets/ — skipping")
        return True
    return True


def _download_hf_sorel(dest: Path) -> bool:
    """Download SOREL-20M 100K sample from HuggingFace (requires auth)."""
    from huggingface_hub import hf_hub_download

    if dest.exists():
        log.info("  Already exists: %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
        return True

    log.info("  Downloading SOREL-20M 100K sample from HuggingFace...")
    log.info("  NOTE: This dataset requires accepting terms at:")
    log.info("    https://huggingface.co/datasets/reveng-grp-2025/sorel20m-100k")
    log.info("  You must log in with: huggingface-cli login")

    try:
        path = hf_hub_download(
            repo_id="reveng-grp-2025/sorel20m-100k",
            filename="train.parquet",
            repo_type="dataset",
        )
        import shutil
        shutil.copy2(path, dest)
        log.info("  Downloaded: %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
        return True
    except Exception as e:
        log.warning("  Failed: %s", e)
        log.info("  Suggestion: visit https://huggingface.co/datasets/reveng-grp-2025/sorel20m-100k")
        log.info("  and accept terms, then run: huggingface-cli login")
        return False


def _ensure_extracted(path: Path) -> bool:
    """Check if extracted content already exists."""
    if path.suffix == ".zip":
        # Check if there's a directory sibling
        dir_name = path.stem
        if (path.parent / dir_name).exists():
            return True
    return False


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------


def download_file(url: str, dest: Path, desc: str = "") -> bool:
    """Download a single file with progress."""
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        size_mb = dest.stat().st_size / (1024 * 1024)
        log.info("  Already exists: %s (%.1f MB)", dest.name, size_mb)
        return True

    log.info("  Downloading %s ...", desc or url)
    try:
        resp = requests.get(url, stream=True, timeout=TIMEOUT, allow_redirects=True)
        resp.raise_for_status()

        total = int(resp.headers.get("content-length", 0))
        downloaded = 0
        with open(dest, "wb") as f:
            for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total and downloaded % (CHUNK_SIZE * 4) == 0:
                        pct = min(100, downloaded / total * 100)
                        log.info("    %s: %.0f%% (%.0f / %.0f MB)", dest.name, pct, downloaded / 1e6, total / 1e6)

        size_mb = dest.stat().st_size / (1024 * 1024)
        log.info("  Downloaded: %s (%.1f MB)", dest.name, size_mb)
        return True

    except requests.exceptions.RequestException as e:
        log.warning("  Failed: %s — %s", url, e)
        if dest.exists():
            dest.unlink()
        return False


def extract_archive(path: Path) -> bool:
    """Extract common archive formats."""
    if not path.exists():
        return False

    extract_dir = path.parent
    suffix = "".join(path.suffixes)

    if suffix.endswith(".zip"):
        log.info("  Extracting %s to %s ...", path.name, extract_dir)
        try:
            with zipfile.ZipFile(path) as zf:
                zf.extractall(extract_dir)
            log.info("  Extracted: %s", path.name)
            return True
        except Exception as e:
            log.warning("  Extract failed: %s", e)
            return False

    elif suffix.endswith((".tar.gz", ".tgz", ".tar.bz2")):
        log.info("  Extracting %s to %s ...", path.name, extract_dir)
        try:
            shutil.unpack_archive(str(path), str(extract_dir))
            log.info("  Extracted: %s", path.name)
            return True
        except Exception as e:
            log.warning("  Extract failed: %s", e)
            return False

    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser(description="Download ML training datasets")
    p.add_argument("--dry-run", action="store_true", help="Show what would be downloaded")
    p.add_argument(
        "--model", "-m", type=str, default=None,
        choices=["pe", "network", "behavior", "ransomware", "memory_injection",
                 "lolbin", "supply_chain", "aigen", "identity", "all"],
        help="Filter datasets by model",
    )
    args = p.parse_args()

    log.info("=" * 60)
    log.info("EDR Dataset Downloader v2")
    log.info("Target: %s", DATASETS_DIR)
    log.info("=" * 60)

    available = shutil.disk_usage(DATASETS_DIR)
    log.info("Free disk space: %.1f GB\n", available.free / (1024**3))

    # Filter sources
    filtered = []
    for s in SOURCES:
        name, url, path, size, desc, models, extract = s
        path_obj = DATASETS_DIR / path if isinstance(path, str) else None

        if args.model and args.model != "all" and args.model not in models:
            continue

        filtered.append(s)

    log.info("Sources: %d\n", len(filtered))

    ok = 0
    fail = 0
    skip = 0

    for name, url, path, size, desc, models, extract in filtered:
        # Resolve destination
        if callable(path):
            dest = DATASETS_DIR / "custom" / name
        else:
            dest = DATASETS_DIR / path

        log.info("[%s] %s (%s)", name, desc, size)
        log.info("  Dest: %s", dest)

        if args.dry_run:
            log.info("  [DRY RUN]\n")
            skip += 1
            continue

        # Custom download function
        if callable(url):
            success = url(dest)
        else:
            success = download_file(url, dest, desc)

        if success:
            ok += 1
            if extract and dest.suffix in (".zip", ".gz", ".bz2"):
                extract_archive(dest)
        else:
            fail += 1

        log.info("")

    log.info("=" * 60)
    log.info("Summary: %d OK, %d failed, %d skipped", ok, fail, skip)
    log.info("=" * 60)
    sys.exit(0 if fail == 0 else 1)


if __name__ == "__main__":
    main()
