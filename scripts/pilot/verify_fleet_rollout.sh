#!/usr/bin/env bash
# End-to-end fleet rollout verification on the control plane.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST="${1:-}"
EXPECTED="${2:-}"

if [[ -z "${HOST}" ]]; then
	echo "usage: $0 <control-plane-host> [expected-agents]" >&2
	echo "  env: EDR_CONTROLPLANE_HTTPS=1, EDR_CONTROLPLANE_API_TOKEN=..." >&2
	echo "       EDR_ROLLOUT_VALIDATE=1 (also run heartbeat stale gate)" >&2
	exit 1
fi

export EDR_CONTROL_PLANE_HOST="${HOST}"

echo "==> Step 1: control plane health"
bash "${ROOT}/scripts/pilot/verify_controlplane.sh" "${HOST}"

echo
echo "==> Step 2: fleet rollout status"
bash "${ROOT}/scripts/pilot/rollout_status.sh" "${HOST}" "${EXPECTED}"

if [[ "${EDR_ROLLOUT_VALIDATE:-0}" == "1" || "${EDR_ROLLOUT_VALIDATE:-0}" == "true" ]]; then
	echo
	echo "==> Step 3: rollout validation gate"
	bash "${ROOT}/scripts/pilot/run_rollout_validation.sh" "${HOST}" "${EXPECTED:-1}"
fi

if [[ -n "${EDR_CONTROLPLANE_API_TOKEN:-}" ]]; then
	linux_cfg="/etc/edr-agent/config.yml"
	macos_cfg="/Library/Application Support/EDR/config.yml"
	active=""
	for cfg in "${linux_cfg}" "${macos_cfg}"; do
		if [[ -f "${cfg}" ]]; then
			active="${cfg}"
			break
		fi
	done
	if [[ -n "${active}" ]] && command -v edrctl >/dev/null 2>&1; then
		echo
		bash "${ROOT}/scripts/pilot/pilot_fleet_check.sh" "${active}" || true
	fi
fi

if [[ "${EDR_ROLLOUT_VERIFY_POLICY:-0}" == "1" || "${EDR_ROLLOUT_VERIFY_POLICY:-0}" == "true" ]]; then
	echo
	echo "==> control plane policy bundles"
	bash "${ROOT}/scripts/pilot/verify_controlplane_policy.sh" "${HOST}"
fi

echo
echo "fleet rollout verification OK"
