#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/rules/ioc"
mkdir -p "${OUT_DIR}"

fetch() {
  local name="$1"
  local url="$2"
  echo "fetching ${name}"
  curl -fsSL "${url}" -o "${OUT_DIR}/${name}"
}

fetch "urlhaus.csv" "https://urlhaus.abuse.ch/downloads/csv_recent/"
fetch "feodotracker.csv" "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
fetch "sslbl.csv" "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
fetch "spamhaus_drop.txt" "https://www.spamhaus.org/drop/drop.txt"
fetch "tor_exit_nodes.txt" "https://check.torproject.org/torbulkexitlist"
fetch "cisa_kev.json" "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

echo "intel sync complete"
