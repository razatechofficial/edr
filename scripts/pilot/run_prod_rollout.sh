#!/usr/bin/env bash
# Production rollout orchestrator (run from control plane host).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST="${1:-}"
EXPECTED="${2:-1}"

if [[ -z "${HOST}" ]]; then
	echo "usage: $0 <control-plane-host> [expected-agents]" >&2
	echo "  env: EDR_ROLLOUT_DEPLOY_CP=1, EDR_ROLLOUT_ENABLE_TLS=1" >&2
	echo "       EDR_PILOT_MTLS=1, EDR_CONTROLPLANE_HTTPS=1, EDR_CONTROLPLANE_API_TOKEN=..." >&2
	echo "       EDR_PILOT_WAIT_AGENTS=1, EDR_PILOT_VERIFY_ENROLLMENT=1, EDR_PILOT_VERIFY_DETECTION=1" >&2
	echo "       EDR_ROLLOUT_VALIDATE=1" >&2
	echo "       EDR_ROLLOUT_FETCH_ARTIFACTS=1, EDR_ROLLOUT_STAGE_BUNDLE=1" >&2
	exit 1
fi

export EDR_CONTROL_PLANE_HOST="${HOST}"

if [[ "${EDR_ROLLOUT_DEPLOY_CP:-0}" == "1" || "${EDR_ROLLOUT_DEPLOY_CP:-0}" == "true" ]]; then
	echo "==> deploy control plane"
	sudo make -C "${ROOT}" deploy-controlplane
fi

if [[ "${EDR_ROLLOUT_ENABLE_TLS:-0}" == "1" || "${EDR_ROLLOUT_ENABLE_TLS:-0}" == "true" ]]; then
	echo "==> enable control plane TLS/mTLS"
	sudo make -C "${ROOT}" enable-controlplane-tls HOST="${HOST}"
	export EDR_CONTROLPLANE_HTTPS=1
	if [[ -z "${EDR_CONTROLPLANE_API_TOKEN:-}" && -f /etc/edr-controlplane/env ]]; then
		export EDR_CONTROLPLANE_API_TOKEN="$(grep -E '^EDR_CONTROLPLANE_API_TOKEN=' /etc/edr-controlplane/env | cut -d= -f2- || true)"
	fi
fi

export EDR_PILOT_MTLS="${EDR_PILOT_MTLS:-1}"
bash "${ROOT}/scripts/pilot/run_fleet_pilot.sh" "${HOST}" "${EXPECTED}"

if [[ "${EDR_ROLLOUT_VALIDATE:-0}" == "1" || "${EDR_ROLLOUT_VALIDATE:-0}" == "true" ]]; then
	echo
	echo "==> rollout validation gate"
	bash "${ROOT}/scripts/pilot/run_rollout_validation.sh" "${HOST}" "${EXPECTED}"
fi

if [[ "${EDR_ROLLOUT_FETCH_ARTIFACTS:-0}" == "1" || "${EDR_ROLLOUT_FETCH_ARTIFACTS:-0}" == "true" ]]; then
	echo
	echo "==> fetch release artifacts"
	bash "${ROOT}/scripts/pilot/fetch_release_artifacts.sh" "${EDR_ROLLOUT_RELEASE_TAG:-}" "${EDR_ROLLOUT_PACKAGE_DIR:-${ROOT}/dist/release}"
fi

if [[ "${EDR_ROLLOUT_STAGE_BUNDLE:-0}" == "1" || "${EDR_ROLLOUT_STAGE_BUNDLE:-0}" == "true" ]]; then
	echo
	echo "==> stage offline fleet rollout bundle"
	EDR_ROLLOUT_PACKAGE_DIR="${EDR_ROLLOUT_PACKAGE_DIR:-${ROOT}/dist/release}" \
		bash "${ROOT}/scripts/pilot/stage_fleet_rollout_bundle.sh" "${EDR_ROLLOUT_BUNDLE_DIR:-${ROOT}/dist/fleet-rollout-bundle}"
fi

echo
echo "Endpoint enrollment check:"
echo "  edrctl fleet check --https --token \$EDR_CONTROLPLANE_API_TOKEN --ca-cert /etc/edr-controlplane/tls/ca.crt"
echo
echo "Offline/airgap bundle (control plane):"
echo "  EDR_ROLLOUT_WAIT_RELEASE=1 bash scripts/pilot/prepare_fleet_rollout.sh"
echo "  or: make prepare-fleet-rollout WAIT=1"
