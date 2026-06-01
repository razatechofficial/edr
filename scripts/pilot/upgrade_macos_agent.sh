#!/usr/bin/env bash
# Upgrade an installed macOS agent package while preserving config and agent_id.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG="${1:-}"

if [[ -z "${PKG}" ]]; then
	echo "usage: $0 dist/edr-agent_<version>_<arch>.pkg" >&2
	exit 1
fi
if [[ ! -f "${PKG}" ]]; then
	echo "package not found: ${PKG}" >&2
	exit 1
fi
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

bash "${ROOT}/scripts/verify_macos_pkg.sh" "${PKG}"

echo "==> upgrade edr-agent from ${PKG}"
installer -pkg "${PKG}" -target /

LABEL="system/com.razatech.edr-agent"
launchctl kickstart -k "${LABEL}" 2>/dev/null || launchctl bootstrap system /Library/LaunchDaemons/com.razatech.edr-agent.plist 2>/dev/null || true
sleep 3

if ! launchctl print "${LABEL}" >/dev/null 2>&1; then
	echo "ERROR: edr-agent launchd job not loaded after upgrade" >&2
	exit 1
fi

CP_HOST="${EDR_CONTROL_PLANE_HOST:-}"
if [[ -n "${CP_HOST}" ]]; then
	bash "${ROOT}/scripts/pilot/verify_macos_tenant.sh" "${CP_HOST}"
else
	bash "${ROOT}/scripts/pilot/verify_macos_tenant.sh"
fi

echo "macOS agent upgrade OK"
