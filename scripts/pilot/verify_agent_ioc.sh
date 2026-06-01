#!/usr/bin/env bash
# Verify offline IOC databases are present on the local agent.
set -euo pipefail

TARGET="${1:-auto}"

resolve_paths() {
	case "${TARGET}" in
	auto)
		case "$(uname -s)" in
		Darwin)
			TARGET="macos"
			;;
		MINGW*|MSYS*|CYGWIN*)
			TARGET="windows"
			;;
		*)
			if [[ "${OS:-}" == "Windows_NT" ]]; then
				TARGET="windows"
			else
				TARGET="linux"
			fi
			;;
		esac
		;&
	linux)
		DIR="${EDR_IOC_DIR:-/etc/edr-agent/rules/ioc}"
		;;
	macos)
		DIR="${EDR_IOC_DIR:-/Library/Application Support/EDR/config/rules/ioc}"
		;;
	windows)
		DIR="${EDR_IOC_DIR:-${PROGRAMDATA:-/c/ProgramData}/EDR Agent/rules/ioc}"
		;;
	*)
		echo "usage: $0 [linux|macos|windows|auto]" >&2
		exit 1
		;;
	esac
}

resolve_paths

python3 - <<'PY' "${DIR}"
import json, os, sys

ioc_dir = sys.argv[1]
required = ["hashes.json", "ips.csv", "domains.csv"]
missing = [name for name in required if not os.path.isfile(os.path.join(ioc_dir, name))]
if missing:
    raise SystemExit(f"ERROR: missing IOC files in {ioc_dir}: {', '.join(missing)}")

hash_count = 0
with open(os.path.join(ioc_dir, "hashes.json"), encoding="utf-8") as f:
    data = json.load(f)
    if isinstance(data, list):
        hash_count = len(data)

def csv_rows(path):
    with open(path, encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    return max(0, len(lines) - 1)

ip_count = csv_rows(os.path.join(ioc_dir, "ips.csv"))
domain_count = csv_rows(os.path.join(ioc_dir, "domains.csv"))

print(f"IOC directory: {ioc_dir}")
print(f"  hashes: {hash_count}")
print(f"  ips: {ip_count}")
print(f"  domains: {domain_count}")

if hash_count == 0 and ip_count == 0 and domain_count == 0:
    raise SystemExit("ERROR: IOC databases are empty")

print("agent IOC OK")
PY
