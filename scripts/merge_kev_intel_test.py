#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from merge_kev_intel import merge_kev


class MergeKEVTest(unittest.TestCase):
    def test_extracts_hashes_and_builds_catalog(self) -> None:
        sample = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vendorProject": "Example Vendor",
                    "product": "Example Product",
                    "vulnerabilityName": "Example RCE",
                    "dateAdded": "2024-01-01",
                    "dueDate": "2024-01-15",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "Indicator sha256 deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "cwes": ["CWE-787"],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kev.json"
            path.write_text(json.dumps(sample), encoding="utf-8")
            catalog, hashes = merge_kev(path)

        self.assertEqual(len(catalog), 1)
        self.assertEqual(catalog[0]["cve_id"], "CVE-2024-0001")
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]["type"], "sha256")
        self.assertIn("cisa-kev", hashes[0]["tags"])


if __name__ == "__main__":
    unittest.main()
