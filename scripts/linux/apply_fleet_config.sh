#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

FLEET="/etc/edr-agent/config.fleet.yml"
ACTIVE="/etc/edr-agent/config.yml"

if [[ ! -f "${FLEET}" ]]; then
	echo "ERROR: Missing ${FLEET}. Reinstall the package or copy configs/linux/config.fleet.yml." >&2
	exit 1
fi

cp "${FLEET}" "${ACTIVE}"
systemctl restart edr-agent
echo "Applied fleet config and restarted edr-agent."
