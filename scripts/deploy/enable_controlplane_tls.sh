#!/usr/bin/env bash
# Generate TLS material (if needed), enable mTLS in control-plane env, and restart.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TLS_DIR="${TLS_DIR:-/etc/edr-controlplane/tls}"
ENV_FILE="${ENV_FILE:-/etc/edr-controlplane/env}"
HOST="${1:-}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo)." >&2
	exit 1
fi

if [[ -n "${HOST}" ]]; then
	export TLS_CN="${HOST}"
	export TLS_SAN="DNS:${HOST},DNS:localhost,IP:127.0.0.1"
fi

bash "${ROOT}/scripts/deploy/generate_controlplane_tls.sh" "${TLS_DIR}"

touch "${ENV_FILE}"
upsert_env() {
	local key="$1"
	local val="$2"
	if grep -q "^${key}=" "${ENV_FILE}"; then
		sed -i.bak "s|^${key}=.*|${key}=${val}|" "${ENV_FILE}"
	else
		echo "${key}=${val}" >> "${ENV_FILE}"
	fi
}

upsert_env EDR_CONTROLPLANE_TLS_CERT "${TLS_DIR}/server.crt"
upsert_env EDR_CONTROLPLANE_TLS_KEY "${TLS_DIR}/server.key"
upsert_env EDR_CONTROLPLANE_TLS_CLIENT_CA "${TLS_DIR}/ca.crt"
upsert_env EDR_CONTROLPLANE_MUTUAL_TLS true

systemctl restart edr-controlplane

echo "Control plane mTLS enabled."
echo "  Agent ca_cert:   ${TLS_DIR}/ca.crt"
echo "  Agent tls_cert:  ${TLS_DIR}/agent-client.crt"
echo "  Agent tls_key:   ${TLS_DIR}/agent-client.key"
echo "  Verify: EDR_CONTROLPLANE_HTTPS=1 bash ${ROOT}/scripts/pilot/verify_controlplane.sh ${HOST:-localhost}"
