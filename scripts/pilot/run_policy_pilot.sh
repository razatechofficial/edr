#!/usr/bin/env bash
# Stage CP policy and verify agent received matching rule bundles.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"
STAGE="${EDR_POLICY_PILOT_STAGE:-0}"
WAIT="${EDR_POLICY_PILOT_WAIT:-1}"

if [[ -z "${HOST}" ]]; then
	echo "usage: $0 <control-plane-host>" >&2
	echo "  env: EDR_POLICY_PILOT_STAGE=1 (sudo stage on this host)" >&2
	echo "       EDR_POLICY_PILOT_WAIT=0 (skip wait loop)" >&2
	echo "       EDR_CONTROLPLANE_HTTPS=1, EDR_CONTROLPLANE_API_TOKEN=..." >&2
	exit 1
fi

if [[ "${STAGE}" == "1" || "${STAGE}" == "true" ]]; then
	echo "==> stage control plane policy"
	sudo bash "${ROOT}/scripts/deploy/stage_controlplane_policy.sh"
	echo "==> restart control plane"
	sudo systemctl restart edr-controlplane
	sleep 2
fi

echo "==> verify control plane policy"
bash "${ROOT}/scripts/pilot/verify_controlplane_policy.sh" "${HOST}"

if [[ "${WAIT}" == "1" || "${WAIT}" == "true" ]]; then
	echo
	echo "==> wait for agent policy sync"
	bash "${ROOT}/scripts/pilot/wait_for_policy_sync.sh" "${HOST}"
else
	echo
	echo "==> verify agent policy hash (no wait)"
	bash "${ROOT}/scripts/pilot/verify_agent_policy_sync.sh"
	bash "${ROOT}/scripts/pilot/verify_policy_sync.sh" "${HOST}"
fi

echo "policy pilot OK"
