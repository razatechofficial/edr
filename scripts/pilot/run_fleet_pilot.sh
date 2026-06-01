#!/usr/bin/env bash
# End-to-end fleet pilot helper: verify control plane and print endpoint apply steps.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST="${1:-}"
MTLS="${EDR_PILOT_MTLS:-0}"
WAIT="${EDR_PILOT_WAIT_AGENTS:-0}"

if [[ -z "${HOST}" ]]; then
	echo "usage: $0 <control-plane-host> [expected-agents]" >&2
	echo "  env: EDR_PILOT_MTLS=1, EDR_CONTROLPLANE_HTTPS=1, EDR_CONTROLPLANE_API_TOKEN=..." >&2
	exit 1
fi

EXPECTED="${2:-1}"
export EDR_CONTROL_PLANE_HOST="${HOST}"

echo "==> Step 1: verify control plane"
bash "${ROOT}/scripts/pilot/verify_controlplane.sh" "${HOST}"

echo
echo "==> Step 2: apply tenant profiles on endpoints"
if [[ "${MTLS}" == "1" || "${MTLS}" == "true" ]]; then
	cat <<EOF
Linux:
  sudo scripts/deploy/distribute_agent_tls.sh /etc/edr-controlplane/tls <agent-host>
  sudo scripts/linux/apply_tenant_tls_config.sh ${HOST}
  bash scripts/pilot/verify_linux_tenant.sh ${HOST}

macOS:
  sudo mkdir -p "/Library/Application Support/EDR/tls"
  sudo cp /path/to/{ca.crt,agent-client.crt,agent-client.key} "/Library/Application Support/EDR/tls/"
  sudo scripts/macos/apply_tenant_tls_config.sh ${HOST}
  bash scripts/pilot/verify_macos_tenant.sh ${HOST}

Windows (Admin):
  copy TLS files to C:\\ProgramData\\EDR Agent\\tls\\
  apply_tenant_tls_config.bat ${HOST}
  powershell -File scripts\\pilot\\verify_windows_tenant.ps1
EOF
else
	cat <<EOF
Linux:
  sudo scripts/linux/apply_tenant_config.sh ${HOST}
  bash scripts/pilot/verify_linux_tenant.sh ${HOST}

macOS:
  sudo scripts/macos/apply_tenant_config.sh ${HOST}
  bash scripts/pilot/verify_macos_tenant.sh ${HOST}

Windows (Admin):
  apply_tenant_config.bat ${HOST}
  powershell -File scripts\\pilot\\verify_windows_tenant.ps1
EOF
fi

if [[ "${WAIT}" == "1" || "${WAIT}" == "true" ]]; then
	echo
	echo "==> Step 3: waiting for ${EXPECTED} enrolled agent(s)"
	bash "${ROOT}/scripts/pilot/wait_for_agents.sh" "${HOST}" "${EXPECTED}"
fi

echo
echo "Fleet pilot checklist complete for ${HOST}"
