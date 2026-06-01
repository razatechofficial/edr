#!/usr/bin/env bash
# Pre-flight checks before production fleet rollout (run on control plane host).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"

missing=0
warn=0

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "ERROR: missing command: $1" >&2
		missing=$((missing + 1))
	fi
}

need_cmd curl
need_cmd python3
need_cmd ssh
need_cmd scp

if [[ "${EDR_ROLLOUT_DEPLOY_CP:-0}" == "1" || "${EDR_ROLLOUT_DEPLOY_CP:-0}" == "true" ]]; then
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: EDR_ROLLOUT_DEPLOY_CP=1 requires root (sudo)" >&2
		missing=$((missing + 1))
	fi
fi

if [[ "${EDR_ROLLOUT_ENABLE_TLS:-0}" == "1" || "${EDR_ROLLOUT_ENABLE_TLS:-0}" == "true" ]]; then
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: EDR_ROLLOUT_ENABLE_TLS=1 requires root (sudo)" >&2
		missing=$((missing + 1))
	fi
fi

if [[ "${EDR_ROLLOUT_FETCH_ARTIFACTS:-0}" == "1" || "${EDR_ROLLOUT_FETCH_ARTIFACTS:-0}" == "true" \
	|| "${EDR_ROLLOUT_WAIT_RELEASE:-0}" == "1" || "${EDR_ROLLOUT_WAIT_RELEASE:-0}" == "true" ]]; then
	need_cmd gh
fi

TLS_DIR="${EDR_CONTROLPLANE_TLS_DIR:-/etc/edr-controlplane/tls}"
if [[ "${EDR_PILOT_MTLS:-1}" == "1" || "${EDR_PILOT_MTLS:-1}" == "true" \
	|| "${EDR_ROLLOUT_ENABLE_TLS:-0}" == "1" || "${EDR_ROLLOUT_ENABLE_TLS:-0}" == "true" ]]; then
	for f in ca.crt server.crt server.key agent-client.crt agent-client.key; do
		if [[ ! -f "${TLS_DIR}/${f}" ]]; then
			echo "WARNING: missing TLS file ${TLS_DIR}/${f}" >&2
			warn=$((warn + 1))
		fi
	done
fi

if [[ -f /etc/edr-controlplane/env ]]; then
	if grep -qE '^EDR_CONTROLPLANE_API_TOKEN=' /etc/edr-controlplane/env; then
		echo "control plane API token: present in /etc/edr-controlplane/env"
	else
		echo "WARNING: /etc/edr-controlplane/env has no EDR_CONTROLPLANE_API_TOKEN" >&2
		warn=$((warn + 1))
	fi
elif [[ -z "${EDR_CONTROLPLANE_API_TOKEN:-}" ]]; then
	echo "WARNING: no EDR_CONTROLPLANE_API_TOKEN (HTTP admin routes may be open)" >&2
	warn=$((warn + 1))
fi

if [[ -n "${HOST}" ]]; then
	echo "control plane host: ${HOST}"
fi
echo "repo root: ${ROOT}"

if [[ "${missing}" -gt 0 ]]; then
	echo "preflight FAILED (${missing} blocking issue(s))" >&2
	exit 1
fi

if [[ "${warn}" -gt 0 ]]; then
	echo "preflight OK with ${warn} warning(s)"
else
	echo "preflight OK"
fi
