#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

ENTERPRISE="/etc/edr-agent/config.enterprise.yml"
ACTIVE="/etc/edr-agent/config.yml"

if [[ ! -f "${ENTERPRISE}" ]]; then
	echo "ERROR: Missing ${ENTERPRISE}. Reinstall the package or copy configs/linux/config.enterprise.yml." >&2
	exit 1
fi

cp "${ENTERPRISE}" "${ACTIVE}"
systemctl restart edr-agent
echo "Applied enterprise config (ML enabled) and restarted edr-agent."
