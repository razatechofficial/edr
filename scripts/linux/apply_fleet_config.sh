#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

FLEET="/etc/edr-agent/config.fleet.yml"
ACTIVE="/etc/edr-agent/config.yml"

if [[ ! -f "${FLEET}" ]]; then
	echo "ERROR: Missing ${FLEET}. Reinstall the package or copy configs/linux/config.fleet.yml." >&2
	exit 1
fi

cp "${FLEET}" "${ACTIVE}"

if [[ -n "${HOST}" ]]; then
	bash "${ROOT}/scripts/shared/patch_config_endpoint.sh" "${ACTIVE}" "${HOST}"
	echo "Patched server.endpoint=${HOST}"
else
	echo "WARNING: No control plane host set. Pass host as arg or set EDR_CONTROL_PLANE_HOST." >&2
fi

systemctl restart edr-agent
echo "Applied fleet config and restarted edr-agent."
