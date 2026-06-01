#!/usr/bin/env bash
# Backup control plane state, TLS material, and env for disaster recovery.
set -euo pipefail

OUT="${1:-}"
DATA_DIR="${EDR_CONTROLPLANE_DATA:-/var/lib/edr-controlplane}"
ENV_DIR="${EDR_CONTROLPLANE_ENV_DIR:-/etc/edr-controlplane}"
TLS_DIR="${EDR_CONTROLPLANE_TLS_DIR:-${ENV_DIR}/tls}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

if [[ -z "${OUT}" ]]; then
	OUT="/var/backups/edr-controlplane-${STAMP}.tar.gz"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
mkdir -p "${TMP}/data" "${TMP}/config"

if [[ -d "${DATA_DIR}" ]]; then
	cp -a "${DATA_DIR}/." "${TMP}/data/"
fi
if [[ -f "${ENV_DIR}/env" ]]; then
	cp "${ENV_DIR}/env" "${TMP}/config/env"
fi
if [[ -d "${TLS_DIR}" ]]; then
	cp -a "${TLS_DIR}" "${TMP}/config/tls"
fi

cat > "${TMP}/MANIFEST.txt" <<EOF
edr-controlplane backup ${STAMP}
data_dir=${DATA_DIR}
env_file=${ENV_DIR}/env
tls_dir=${TLS_DIR}
EOF

mkdir -p "$(dirname "${OUT}")"
tar -czf "${OUT}" -C "${TMP}" .
echo "control plane backup written: ${OUT}"
