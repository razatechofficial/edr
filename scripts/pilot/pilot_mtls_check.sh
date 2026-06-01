#!/usr/bin/env bash
# Verify mTLS material exists when mutual_tls is enabled in the active config.
set -euo pipefail

ACTIVE="${1:-}"
TLS_DIR="${2:-}"

if [[ -z "${ACTIVE}" || -z "${TLS_DIR}" ]]; then
	echo "usage: $0 <active-config> <tls-dir>" >&2
	exit 1
fi
if ! grep -Eq '^[[:space:]]*mutual_tls:[[:space:]]*true' "${ACTIVE}"; then
	exit 0
fi

echo "==> mTLS client material (${TLS_DIR})"
for f in ca.crt agent-client.crt agent-client.key; do
	if [[ ! -f "${TLS_DIR}/${f}" ]]; then
		echo "ERROR: missing ${TLS_DIR}/${f}" >&2
		exit 1
	fi
done
echo "mTLS material present"
