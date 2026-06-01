#!/usr/bin/env bash
# Restore control plane state, TLS material, and env from a backup archive.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCHIVE="${1:-}"
DATA_DIR="${EDR_CONTROLPLANE_DATA:-/var/lib/edr-controlplane}"
ENV_DIR="${EDR_CONTROLPLANE_ENV_DIR:-/etc/edr-controlplane}"
ENV_FILE="${ENV_DIR}/env"
TLS_DIR="${EDR_CONTROLPLANE_TLS_DIR:-${ENV_DIR}/tls}"
SERVICE_USER="${SERVICE_USER:-edr-controlplane}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

if [[ -z "${ARCHIVE}" || ! -f "${ARCHIVE}" ]]; then
	echo "usage: $0 <backup.tar.gz>" >&2
	echo "  env: EDR_RESTORE_CONFIRM=1 (required)" >&2
	exit 1
fi
if [[ "${EDR_RESTORE_CONFIRM:-0}" != "1" && "${EDR_RESTORE_CONFIRM:-0}" != "true" ]]; then
	echo "ERROR: set EDR_RESTORE_CONFIRM=1 to restore over live control plane state" >&2
	exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
tar -xzf "${ARCHIVE}" -C "${TMP}"

if [[ ! -f "${TMP}/MANIFEST.txt" ]]; then
	echo "ERROR: backup missing MANIFEST.txt: ${ARCHIVE}" >&2
	exit 1
fi
if [[ ! -d "${TMP}/data" ]]; then
	echo "ERROR: backup missing data/: ${ARCHIVE}" >&2
	exit 1
fi

echo "==> pre-restore safety backup"
PRE="${EDR_RESTORE_PREBACKUP:-/var/backups/edr-controlplane-pre-restore-${STAMP}.tar.gz}"
bash "${ROOT}/scripts/deploy/backup_controlplane.sh" "${PRE}"

echo "==> stop control plane"
systemctl stop edr-controlplane || true

echo "==> restore data to ${DATA_DIR}"
install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${DATA_DIR}"
find "${DATA_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp -a "${TMP}/data/." "${DATA_DIR}/"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
chmod 0750 "${DATA_DIR}"

if [[ -f "${TMP}/config/env" ]]; then
	echo "==> restore env ${ENV_FILE}"
	install -d -m 0755 "${ENV_DIR}"
	install -m 0644 "${TMP}/config/env" "${ENV_FILE}"
fi

if [[ -d "${TMP}/config/tls" ]]; then
	echo "==> restore TLS ${TLS_DIR}"
	rm -rf "${TLS_DIR}"
	cp -a "${TMP}/config/tls" "${TLS_DIR}"
	chmod 0750 "${TLS_DIR}"
fi

echo "==> start control plane"
systemctl daemon-reload
systemctl start edr-controlplane
sleep 2
if ! systemctl is-active --quiet edr-controlplane; then
	systemctl status edr-controlplane --no-pager || true
	echo "ERROR: edr-controlplane failed to start after restore" >&2
	exit 1
fi

if [[ "${EDR_RESTORE_SKIP_VERIFY:-0}" != "1" && "${EDR_RESTORE_SKIP_VERIFY:-0}" != "true" ]]; then
	if [[ -f "${ENV_FILE}" ]] && grep -q '^EDR_CONTROLPLANE_API_TOKEN=' "${ENV_FILE}"; then
		export EDR_CONTROLPLANE_API_TOKEN="$(grep -E '^EDR_CONTROLPLANE_API_TOKEN=' "${ENV_FILE}" | cut -d= -f2-)"
	fi
	if grep -q '^EDR_CONTROLPLANE_MUTUAL_TLS=true' "${ENV_FILE}" 2>/dev/null; then
		export EDR_CONTROLPLANE_HTTPS=1
	fi
	echo "==> verify restored control plane"
	bash "${ROOT}/scripts/pilot/verify_controlplane.sh" localhost
fi

echo "control plane restored from ${ARCHIVE}"
echo "  pre-restore backup: ${PRE}"
