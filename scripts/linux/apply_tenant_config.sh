#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

TENANT="/etc/edr-agent/config.tenant.yml"
ACTIVE="/etc/edr-agent/config.yml"
SOURCE="${ROOT}/configs/linux/config.tenant.yml"

if [[ ! -f "${TENANT}" ]]; then
	if [[ ! -f "${SOURCE}" ]]; then
		echo "ERROR: Missing ${SOURCE}" >&2
		exit 1
	fi
	install -m 0644 "${SOURCE}" "${TENANT}"
fi

cp "${TENANT}" "${ACTIVE}"

if [[ -n "${HOST}" ]]; then
	bash "${ROOT}/scripts/shared/patch_config_endpoint.sh" "${ACTIVE}" "${HOST}"
	echo "Patched server.endpoint=${HOST}"
else
	echo "WARNING: No control plane host set. Pass host as arg or set EDR_CONTROL_PLANE_HOST." >&2
fi

systemctl restart edr-agent
echo "Applied enterprise tenant config and restarted edr-agent."
