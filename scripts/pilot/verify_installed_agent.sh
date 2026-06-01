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
MINGW*|MSYS*|CYGWIN*)
	powershell -NoProfile -ExecutionPolicy Bypass -File "${ROOT}/scripts/pilot/verify_installed_agent.ps1" ${CP_HOST:+-ControlPlaneHost "${CP_HOST}"}
	;;
*)
	if [[ "${OS:-}" == "Windows_NT" ]]; then
		powershell -NoProfile -ExecutionPolicy Bypass -File "${ROOT}/scripts/pilot/verify_installed_agent.ps1" ${CP_HOST:+-ControlPlaneHost "${CP_HOST}"}
	else
		echo "ERROR: unsupported platform $(uname -s)" >&2
		exit 1
	fi
	;;
esac
