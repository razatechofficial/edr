#!/usr/bin/env bash
# Install edr-controlplane binary + systemd unit on Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_SRC="${1:-${ROOT}/bin/edr-controlplane}"
SERVICE_USER="${SERVICE_USER:-edr-controlplane}"
DATA_DIR="${EDR_CONTROLPLANE_DATA:-/var/lib/edr-controlplane}"
ENV_DIR="/etc/edr-controlplane"
ENV_FILE="${ENV_DIR}/env"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

if [[ ! -x "${BIN_SRC}" && ! -f "${BIN_SRC}" ]]; then
	echo "building control plane binary..."
	make -C "${ROOT}" build-controlplane
	BIN_SRC="${ROOT}/bin/edr-controlplane"
fi
if [[ ! -f "${BIN_SRC}" ]]; then
	echo "missing binary: ${BIN_SRC}" >&2
	exit 1
fi

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
	useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${DATA_DIR}"
install -d -m 0755 "${ENV_DIR}"
if [[ ! -f "${ENV_FILE}" ]]; then
	install -m 0644 "${ROOT}/deploy/controlplane/env.example" "${ENV_FILE}"
fi

install -m 0755 "${BIN_SRC}" /usr/local/bin/edr-controlplane
install -m 0644 "${ROOT}/deploy/controlplane/edr-controlplane.service" /etc/systemd/system/edr-controlplane.service

systemctl daemon-reload
systemctl enable edr-controlplane
systemctl restart edr-controlplane

echo "edr-controlplane installed."
echo "  HTTP:  http://$(hostname -f 2>/dev/null || hostname):8080/healthz"
echo "  gRPC:  $(hostname -f 2>/dev/null || hostname):50051"
echo "  data:  ${DATA_DIR}"
echo "  env:   ${ENV_FILE}"
echo "  mTLS:  sudo make enable-controlplane-tls HOST=your-cp-hostname"
