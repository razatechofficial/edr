#!/usr/bin/env python3
"""Merge CISA Known Exploited Vulnerabilities feed into IOC artifacts.

Extracts file hashes embedded in KEV text fields and writes a structured
rules/ioc/kev.json catalog for correlation. Hash entries are merged into
hashes.json by convert-intel.sh.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"\b([a-fA-F0-9]{64})\b")
SHA1_RE = re.compile(r"\b([a-fA-F0-9]{40})\b")
MD5_RE = re.compile(r"\b([a-fA-F0-9]{32})\b")


def _scan_hashes(text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for pattern, htype in ((SHA256_RE, "sha256"), (SHA1_RE, "sha1"), (MD5_RE, "md5")):
        for match in pattern.findall(text):
            found.append({"hash": match.lower(), "type": htype})
    return found


def merge_kev(kev_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    data = json.loads(kev_path.read_text(encoding="utf-8"))
    vulns = data.get("vulnerabilities") or []

    catalog: list[dict[str, Any]] = []
    hash_entries: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()

    for item in vulns:
        cve_id = str(item.get("cveID") or "").strip()
        if not cve_id:
            continue

        text = " ".join(
            str(item.get(key) or "")
            for key in ("notes", "shortDescription", "vulnerabilityName")
        )
        hashes = _scan_hashes(text)
        catalog.append(
            {
                "cve_id": cve_id,
                "vendor": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"),
                "due_date": item.get("dueDate"),
                "known_ransomware_use": item.get("knownRansomwareCampaignUse"),
                "required_action": item.get("requiredAction"),
                "cwes": item.get("cwes") or [],
                "hashes": hashes,
            }
        )

        for entry in hashes:
            h = entry["hash"]
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            hash_entries.append(
                {
                    "hash": h,
                    "type": entry["type"],
                    "malware_family": item.get("vulnerabilityName") or cve_id,
                    "source": "cisa-kev",
                    "severity": "critical",
                    "first_seen": item.get("dateAdded"),
                    "tags": ["cisa-kev", cve_id, item.get("vendorProject") or "unknown-vendor"],
                }
            )

    return catalog, hash_entries


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge CISA KEV into IOC artifacts")
    parser.add_argument("--kev", required=True, type=Path, help="Path to cisa_kev.json")
    parser.add_argument("--hashes-out", required=True, type=Path, help="Append hash JSON array")
    parser.add_argument("--kev-out", required=True, type=Path, help="Write structured kev.json")
    args = parser.parse_args()

    if not args.kev.is_file():
        print(f"skip: KEV file missing: {args.kev}", file=sys.stderr)
        return 0

    catalog, hash_entries = merge_kev(args.kev)

    args.kev_out.parent.mkdir(parents=True, exist_ok=True)
    args.kev_out.write_text(
        json.dumps(
            {
                "source": "cisa-kev",
                "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "count": len(catalog),
                "vulnerabilities": catalog,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    args.hashes_out.parent.mkdir(parents=True, exist_ok=True)
    args.hashes_out.write_text(json.dumps(hash_entries, indent=2) + "\n", encoding="utf-8")

    print(f"  wrote {args.kev_out} ({len(catalog)} CVEs)")
    print(f"  extracted {len(hash_entries)} hash IOC(s) from KEV text")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
