#!/usr/bin/env bash
# Opinionated production rollout: deploy CP, TLS, signed policy, fleet verify, backup.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

export EDR_ROLLOUT_DEPLOY_CP="${EDR_ROLLOUT_DEPLOY_CP:-1}"
export EDR_ROLLOUT_ENABLE_TLS="${EDR_ROLLOUT_ENABLE_TLS:-1}"
export EDR_ROLLOUT_PREPARE_IOC="${EDR_ROLLOUT_PREPARE_IOC:-1}"
export EDR_ROLLOUT_STAGE_POLICY="${EDR_ROLLOUT_STAGE_POLICY:-1}"
export EDR_ROLLOUT_VERIFY_POLICY="${EDR_ROLLOUT_VERIFY_POLICY:-1}"
export EDR_ROLLOUT_SIGN_POLICY="${EDR_ROLLOUT_SIGN_POLICY:-1}"
export EDR_ROLLOUT_VALIDATE="${EDR_ROLLOUT_VALIDATE:-1}"
export EDR_ROLLOUT_VERIFY="${EDR_ROLLOUT_VERIFY:-1}"
export EDR_ROLLOUT_BACKUP_CP="${EDR_ROLLOUT_BACKUP_CP:-1}"
export EDR_PILOT_MTLS="${EDR_PILOT_MTLS:-1}"
export EDR_PILOT_WAIT_AGENTS="${EDR_PILOT_WAIT_AGENTS:-1}"
export EDR_PILOT_VERIFY_ENROLLMENT="${EDR_PILOT_VERIFY_ENROLLMENT:-1}"

if [[ -z "${EDR_POLICY_SIGN_KEY:-}" && -f /etc/edr/certs/edr-policy.seed ]]; then
	export EDR_POLICY_SIGN_KEY="/etc/edr/certs/edr-policy.seed"
fi

exec bash "${ROOT}/scripts/pilot/run_prod_rollout.sh" "$@"
