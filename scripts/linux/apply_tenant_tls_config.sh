#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

TENANT="/etc/edr-agent/config.tenant.tls.yml"
ACTIVE="/etc/edr-agent/config.yml"
SOURCE="${ROOT}/configs/linux/config.tenant.tls.yml"

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

for f in /etc/edr-agent/tls/ca.crt /etc/edr-agent/tls/agent-client.crt /etc/edr-agent/tls/agent-client.key; do
	if [[ ! -f "${f}" ]]; then
		echo "ERROR: Missing ${f}. Copy from control plane: scripts/deploy/distribute_agent_tls.sh" >&2
		exit 1
	fi
done

systemctl restart edr-agent
echo "Applied enterprise tenant mTLS config and restarted edr-agent."
