#!/usr/bin/env bash
# Source control plane env for pilot/edrctl commands.
set -euo pipefail

ENV_FILE="${1:-/etc/edr-controlplane/env}"
if [[ ! -f "${ENV_FILE}" ]]; then
	echo "ERROR: missing env file: ${ENV_FILE}" >&2
	exit 1
fi

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

if [[ -f /etc/edr-controlplane/tls/ca.crt ]]; then
	export EDR_CONTROLPLANE_CA="${EDR_CONTROLPLANE_CA:-/etc/edr-controlplane/tls/ca.crt}"
	export EDR_CONTROLPLANE_HTTPS="${EDR_CONTROLPLANE_HTTPS:-1}"
fi

echo "sourced ${ENV_FILE}"
if [[ -n "${EDR_CONTROLPLANE_API_TOKEN:-}" ]]; then
	echo "  EDR_CONTROLPLANE_API_TOKEN=set"
fi
if [[ -n "${EDR_CONTROLPLANE_CA:-}" ]]; then
	echo "  EDR_CONTROLPLANE_CA=${EDR_CONTROLPLANE_CA}"
fi
