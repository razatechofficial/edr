#!/usr/bin/env bash
# Verify SCA compliance policy files are present on the local agent.
set -euo pipefail

TARGET="${1:-auto}"

resolve_paths() {
	case "${TARGET}" in
	auto)
		case "$(uname -s)" in
		Darwin) TARGET="macos" ;;
		MINGW*|MSYS*|CYGWIN*) TARGET="windows" ;;
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
		DIR="${EDR_SCA_DIR:-/etc/edr-agent/rules/compliance/sca/linux}"
		;;
	macos)
		DIR="${EDR_SCA_DIR:-/Library/Application Support/EDR/config/rules/compliance/sca/darwin}"
		;;
	windows)
		DIR="${EDR_SCA_DIR:-${PROGRAMDATA:-/c/ProgramData}/EDR Agent/rules/compliance/sca/windows}"
		;;
	*)
		echo "usage: $0 [linux|macos|windows|auto]" >&2
		exit 1
		;;
	esac
}

resolve_paths

python3 - <<'PY' "${DIR}" "${TARGET}"
import glob, os, sys

sca_dir, platform = sys.argv[1], sys.argv[2]
if not os.path.isdir(sca_dir):
    raise SystemExit(f"ERROR: missing SCA directory: {sca_dir}")

files = sorted(
    p for p in glob.glob(os.path.join(sca_dir, "*"))
    if os.path.isfile(p) and p.lower().endswith((".yml", ".yaml"))
)
print(f"SCA directory ({platform}): {sca_dir}")
print(f"  policy files: {len(files)}")
if not files:
    raise SystemExit("ERROR: no SCA policy files found")
print("agent SCA OK")
PY
