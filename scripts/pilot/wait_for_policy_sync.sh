#!/usr/bin/env bash
# Poll until agent policy hash matches the control plane.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"
DATA_DIR="${2:-${EDR_AGENT_DATA_DIR:-}}"
TIMEOUT="${EDR_POLICY_SYNC_WAIT_SEC:-300}"
INTERVAL="${EDR_POLICY_SYNC_POLL_SEC:-15}"

if [[ -z "${HOST}" ]]; then
	echo "usage: $0 <control-plane-host> [agent-data-dir]" >&2
	exit 1
fi

deadline=$(( $(date +%s) + TIMEOUT ))
attempt=0

echo "==> waiting for policy sync on ${HOST} (timeout ${TIMEOUT}s)"
while true; do
	attempt=$((attempt + 1))
	set +e
	bash "${ROOT}/scripts/pilot/verify_policy_sync.sh" "${HOST}" "${DATA_DIR}"
	code=$?
	set -e
	if [[ "${code}" -eq 0 ]]; then
		echo "policy sync ready"
		exit 0
	fi
	if [[ $(date +%s) -ge ${deadline} ]]; then
		echo "ERROR: timed out waiting for policy sync" >&2
		exit 1
	fi
	echo "attempt ${attempt}: not synced yet; sleeping ${INTERVAL}s"
	sleep "${INTERVAL}"
done
