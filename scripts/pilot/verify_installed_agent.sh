#!/usr/bin/env bash
# Post-install smoke on a fleet endpoint (dispatches to platform tenant verify).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CP_HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"

case "$(uname -s)" in
Linux)
	bash "${ROOT}/scripts/pilot/verify_linux_tenant.sh" "${CP_HOST}"
	;;
Darwin)
	bash "${ROOT}/scripts/pilot/verify_macos_tenant.sh" "${CP_HOST}"
	;;
*)
	echo "ERROR: run scripts/pilot/verify_windows_tenant.ps1 on Windows" >&2
	exit 1
	;;
esac
