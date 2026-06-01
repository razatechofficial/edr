#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ACTIVE="${EDR_CONFIG:-/Library/Application Support/EDR/config/agent.yaml}"
AGENT_ID="${EDR_AGENT_ID_FILE:-/Library/Application Support/EDR/agent_id}"
CP_HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"
LABEL="system/com.razatech.edr-agent"

if [[ ! -f "${ACTIVE}" ]]; then
	echo "ERROR: missing active config: ${ACTIVE}" >&2
	exit 1
fi
if grep -q 'YOUR_CONTROL_PLANE_HOST' "${ACTIVE}"; then
	echo "ERROR: config still contains YOUR_CONTROL_PLANE_HOST; run apply_tenant_config.sh <host>" >&2
	exit 1
fi

echo "==> edr-agent launchd job"
if ! launchctl print "${LABEL}" >/dev/null 2>&1; then
	echo "ERROR: ${LABEL} is not loaded" >&2
	exit 1
fi
echo "status: loaded"

endpoint="$(grep -E '^[[:space:]]*endpoint:' "${ACTIVE}" | head -1 | sed -E 's/.*endpoint:[[:space:]]*"?([^"]+)"?.*/\1/')"
echo "server.endpoint: ${endpoint}"

if [[ ! -f "${AGENT_ID}" ]]; then
	echo "ERROR: missing agent_id (agent not initialized): ${AGENT_ID}" >&2
	exit 1
fi
echo "agent_id: $(tr -d '[:space:]' < "${AGENT_ID}")"

bash "${ROOT}/scripts/pilot/pilot_mtls_check.sh" "${ACTIVE}" "/Library/Application Support/EDR/tls"

if [[ -z "${CP_HOST}" && -n "${endpoint}" ]]; then
	CP_HOST="${endpoint}"
fi
if [[ -n "${CP_HOST}" ]]; then
	grpc_port="$(grep -E '^[[:space:]]*grpc_port:' "${ACTIVE}" | head -1 | awk '{print $2}')"
	grpc_port="${grpc_port:-50051}"
	echo "==> control plane gRPC ${CP_HOST}:${grpc_port}"
	if command -v nc >/dev/null 2>&1; then
		if ! nc -z -w 3 "${CP_HOST}" "${grpc_port}" 2>/dev/null; then
			echo "ERROR: cannot reach control plane gRPC port" >&2
			exit 1
		fi
		echo "gRPC port reachable"
	fi
fi

if command -v edrctl >/dev/null 2>&1; then
	echo "==> edrctl fleet local"
	edrctl --config "${ACTIVE}" fleet local || true
fi

bash "${ROOT}/scripts/pilot/pilot_fleet_check.sh" "${ACTIVE}"

if [[ "${EDR_PILOT_VERIFY_POLICY:-0}" == "1" || "${EDR_PILOT_VERIFY_POLICY:-0}" == "true" ]]; then
	echo "==> agent policy sync"
	bash "${ROOT}/scripts/pilot/verify_agent_policy_sync.sh"
	if [[ -n "${CP_HOST}" && -n "${EDR_CONTROLPLANE_API_TOKEN:-}" ]]; then
		bash "${ROOT}/scripts/pilot/verify_policy_sync.sh" "${CP_HOST}"
	fi
fi

if [[ "${EDR_PILOT_VERIFY_IOC:-0}" == "1" || "${EDR_PILOT_VERIFY_IOC:-0}" == "true" ]]; then
	echo "==> offline IOC databases"
	bash "${ROOT}/scripts/pilot/verify_agent_ioc.sh" macos
fi

if [[ "${EDR_PILOT_VERIFY_SCA:-0}" == "1" || "${EDR_PILOT_VERIFY_SCA:-0}" == "true" ]]; then
	echo "==> SCA compliance policies"
	bash "${ROOT}/scripts/pilot/verify_agent_sca.sh" macos
fi

echo "macOS tenant pilot check OK"
