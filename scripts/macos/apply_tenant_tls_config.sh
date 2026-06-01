#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_DIR="/Library/Application Support/EDR/config"
TLS_DIR="/Library/Application Support/EDR/tls"
TENANT="${CONFIG_DIR}/config.tenant.tls.yml"
ACTIVE="${CONFIG_DIR}/agent.yaml"
SOURCE="${ROOT}/configs/macos/config.tenant.tls.yml"

if [[ ! -f "${TENANT}" ]]; then
	if [[ ! -f "${SOURCE}" ]]; then
		echo "ERROR: Missing ${SOURCE}" >&2
		exit 1
	fi
	install -d -m 0755 "${CONFIG_DIR}"
	install -m 0644 "${SOURCE}" "${TENANT}"
fi

cp "${TENANT}" "${ACTIVE}"

if [[ -n "${HOST}" ]]; then
	bash "${ROOT}/scripts/shared/patch_config_endpoint.sh" "${ACTIVE}" "${HOST}"
	echo "Patched server.endpoint=${HOST}"
else
	echo "WARNING: No control plane host set. Pass host as arg or set EDR_CONTROL_PLANE_HOST." >&2
fi

for f in "${TLS_DIR}/ca.crt" "${TLS_DIR}/agent-client.crt" "${TLS_DIR}/agent-client.key"; do
	if [[ ! -f "${f}" ]]; then
		echo "ERROR: Missing ${f}. Copy TLS material from the control plane host." >&2
		exit 1
	fi
done

bash "${ROOT}/scripts/macos/restart_agent.sh"
echo "Applied enterprise tenant mTLS config and restarted edr-agent."
