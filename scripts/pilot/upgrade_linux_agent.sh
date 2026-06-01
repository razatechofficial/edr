#!/usr/bin/env bash
# Upgrade an installed Linux agent package while preserving config and agent_id.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEB="${1:-}"

if [[ -z "${DEB}" ]]; then
	echo "usage: $0 dist/edr-agent_<version>_amd64.deb" >&2
	exit 1
fi
if [[ ! -f "${DEB}" ]]; then
	echo "package not found: ${DEB}" >&2
	exit 1
fi
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

bash "${ROOT}/scripts/verify_linux_package.sh" "${DEB}"

echo "==> upgrade edr-agent from ${DEB}"
dpkg -i "${DEB}"
systemctl restart edr-agent
sleep 3

if ! systemctl is-active --quiet edr-agent; then
	systemctl status edr-agent --no-pager || true
	echo "ERROR: edr-agent failed to start after upgrade" >&2
	exit 1
fi

CP_HOST="${EDR_CONTROL_PLANE_HOST:-}"
if [[ -n "${CP_HOST}" ]]; then
	bash "${ROOT}/scripts/pilot/verify_linux_tenant.sh" "${CP_HOST}"
else
	bash "${ROOT}/scripts/pilot/verify_linux_tenant.sh"
fi

echo "Linux agent upgrade OK"
