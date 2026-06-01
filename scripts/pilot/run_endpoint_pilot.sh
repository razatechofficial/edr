#!/usr/bin/env bash
# Post-install + optional detection pilot on the local endpoint.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"
DETECT="${EDR_PILOT_VERIFY_DETECTION:-0}"

if [[ -z "${HOST}" ]]; then
	echo "usage: $0 <control-plane-host>" >&2
	echo "  env: EDR_PILOT_VERIFY_DETECTION=1 to run Log4Shell YARA probe" >&2
	echo "       EDR_PILOT_VERIFY_POLICY=1 to wait for CP policy sync" >&2
	echo "       EDR_PILOT_VERIFY_IOC=1 to verify offline IOC databases" >&2
	echo "       EDR_PILOT_VERIFY_SCA=1 to verify SCA compliance policies" >&2
	exit 1
fi

export EDR_CONTROL_PLANE_HOST="${HOST}"

echo "==> Step 1: post-install smoke"
bash "${ROOT}/scripts/pilot/verify_installed_agent.sh" "${HOST}"

if [[ "${DETECT}" == "1" || "${DETECT}" == "true" ]]; then
	echo
	echo "==> Step 2: detection pipeline"
	case "$(uname -s)" in
	MINGW*|MSYS*|CYGWIN*)
		powershell -NoProfile -ExecutionPolicy Bypass -File "${ROOT}/scripts/pilot/verify_detection_pipeline.ps1" "${HOST}"
		;;
	*)
		if [[ "${OS:-}" == "Windows_NT" ]]; then
			powershell -NoProfile -ExecutionPolicy Bypass -File "${ROOT}/scripts/pilot/verify_detection_pipeline.ps1" "${HOST}"
		else
			bash "${ROOT}/scripts/pilot/verify_detection_pipeline.sh" "${HOST}"
		fi
		;;
	esac
fi

if [[ "${EDR_PILOT_VERIFY_POLICY:-0}" == "1" || "${EDR_PILOT_VERIFY_POLICY:-0}" == "true" ]]; then
	echo
	echo "==> policy sync"
	bash "${ROOT}/scripts/pilot/wait_for_policy_sync.sh" "${HOST}"
fi

if [[ "${EDR_PILOT_VERIFY_IOC:-0}" == "1" || "${EDR_PILOT_VERIFY_IOC:-0}" == "true" ]]; then
	echo
	echo "==> offline IOC databases"
	bash "${ROOT}/scripts/pilot/verify_agent_ioc.sh"
fi

if [[ "${EDR_PILOT_VERIFY_SCA:-0}" == "1" || "${EDR_PILOT_VERIFY_SCA:-0}" == "true" ]]; then
	echo
	echo "==> SCA compliance policies"
	bash "${ROOT}/scripts/pilot/verify_agent_sca.sh"
fi

echo "Endpoint pilot OK"
