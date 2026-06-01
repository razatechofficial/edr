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
	echo "       EDR_PILOT_WAIT_AGENTS=1, EDR_PILOT_VERIFY_ENROLLMENT=1, EDR_PILOT_VERIFY_DETECTION=1, EDR_PILOT_VERIFY_POLICY=1, EDR_PILOT_VERIFY_IOC=1, EDR_PILOT_VERIFY_SCA=1" >&2
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
  sudo scripts/deploy/distribute_agent_tls.sh /etc/edr-controlplane/tls <agent-host> linux
  sudo scripts/linux/apply_tenant_tls_config.sh ${HOST}
  bash scripts/pilot/verify_linux_tenant.sh ${HOST}

macOS:
  EDR_SSH_USER=<user> scripts/deploy/distribute_agent_tls.sh /etc/edr-controlplane/tls <agent-host> macos
  sudo scripts/macos/apply_tenant_tls_config.sh ${HOST}
  bash scripts/pilot/verify_macos_tenant.sh ${HOST}

Windows (Admin, OpenSSH):
  EDR_SSH_USER=Administrator scripts/deploy/distribute_agent_tls.sh /etc/edr-controlplane/tls <agent-host> windows
  apply_tenant_tls_config.bat ${HOST}
  powershell -File scripts\\pilot\\verify_windows_tenant.ps1

Post-install + detection (local endpoint):
  EDR_PILOT_VERIFY_DETECTION=1 bash scripts/pilot/run_endpoint_pilot.sh ${HOST}

Policy bundles (control plane + endpoints):
  sudo make stage-controlplane-policy && sudo systemctl restart edr-controlplane
  EDR_PILOT_VERIFY_POLICY=1 bash scripts/pilot/wait_for_policy_sync.sh ${HOST}
  make verify-fleet-policy-rollout HOST=${HOST} EXPECTED=${EXPECTED}

Offline IOC + SCA (airgap endpoints):
  sudo scripts/deploy/install_agent_ioc.sh ioc linux
  sudo scripts/deploy/install_agent_sca.sh sca linux
  EDR_PILOT_VERIFY_IOC=1 EDR_PILOT_VERIFY_SCA=1 bash scripts/pilot/run_endpoint_pilot.sh ${HOST}
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

if [[ "${EDR_PILOT_VERIFY_ENROLLMENT:-0}" == "1" || "${EDR_PILOT_VERIFY_ENROLLMENT:-0}" == "true" ]]; then
	echo
	echo "==> Step 4: verify endpoint enrollment on control plane"
	bash "${ROOT}/scripts/pilot/verify_agent_enrollment.sh" "${HOST}"
fi

if [[ "${EDR_PILOT_VERIFY_DETECTION:-0}" == "1" || "${EDR_PILOT_VERIFY_DETECTION:-0}" == "true" ]]; then
	echo
	echo "==> Step 5: verify detection pipeline (run on enrolled Linux/macOS endpoint)"
	make verify-detection-pilot HOST="${HOST}"
fi

if [[ "${EDR_PILOT_VERIFY_POLICY:-0}" == "1" || "${EDR_PILOT_VERIFY_POLICY:-0}" == "true" ]]; then
	echo
	echo "==> Step 6: verify fleet policy rollout"
	bash "${ROOT}/scripts/pilot/verify_fleet_policy_rollout.sh" "${HOST}" "${EXPECTED}"
fi

if [[ "${EDR_PILOT_VERIFY_IOC:-0}" == "1" || "${EDR_PILOT_VERIFY_IOC:-0}" == "true" ]]; then
	echo
	echo "==> Step 7: verify offline IOC (run on endpoint with ioc/ installed)"
	bash "${ROOT}/scripts/pilot/verify_agent_ioc.sh" || echo "WARNING: IOC verify failed (install ioc/ on endpoint first)" >&2
fi

if [[ "${EDR_PILOT_VERIFY_SCA:-0}" == "1" || "${EDR_PILOT_VERIFY_SCA:-0}" == "true" ]]; then
	echo
	echo "==> Step 8: verify SCA policies (run on endpoint with sca/ installed)"
	bash "${ROOT}/scripts/pilot/verify_agent_sca.sh" || echo "WARNING: SCA verify failed (install sca/ on endpoint first)" >&2
fi

echo
echo "Fleet status from control plane host:"
echo "  make rollout-status HOST=${HOST} EXPECTED=${EXPECTED}"
echo
echo "Check fleet from control plane host:"
echo "  edrctl fleet agents --host ${HOST} --https --token \$EDR_CONTROLPLANE_API_TOKEN --ca-cert /etc/edr-controlplane/tls/ca.crt"
echo "  edrctl fleet alerts --host ${HOST} --https --token \$EDR_CONTROLPLANE_API_TOKEN --ca-cert /etc/edr-controlplane/tls/ca.crt"
echo
echo "Verify enrollment from an endpoint:"
echo "  edrctl fleet check --https --token \$EDR_CONTROLPLANE_API_TOKEN --ca-cert /etc/edr-controlplane/tls/ca.crt"
echo
echo "Verify a specific agent enrolled on control plane:"
echo "  bash scripts/pilot/verify_agent_enrollment.sh ${HOST} \$(cat /var/lib/edr-agent/agent_id)"
echo
echo "Validate detection -> control plane forwarding on an enrolled endpoint:"
echo "  Linux/macOS: EDR_ALERT_FILE=/var/lib/edr-agent/alerts.jsonl make verify-detection-pilot HOST=${HOST}"
echo "  Windows:     powershell -File scripts\\pilot\\verify_detection_pipeline.ps1 ${HOST}"

echo
echo "Fleet pilot checklist complete for ${HOST}"
