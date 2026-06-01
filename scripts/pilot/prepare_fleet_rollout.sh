#!/usr/bin/env bash
# Download verified release packages and stage an offline fleet rollout bundle.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG="${1:-}"
OUT="${2:-${ROOT}/dist/fleet-rollout-bundle}"
PKG_DIR="${EDR_ROLLOUT_PACKAGE_DIR:-${ROOT}/dist/release}"
WAIT="${EDR_ROLLOUT_WAIT_RELEASE:-0}"

if [[ "${WAIT}" == "1" || "${WAIT}" == "true" ]]; then
	echo "==> wait for prod release CI"
	bash "${ROOT}/scripts/pilot/wait_for_prod_release.sh" "${EDR_RELEASE_BRANCH:-prod}"
fi

echo "==> fetch release artifacts"
bash "${ROOT}/scripts/pilot/fetch_release_artifacts.sh" "${TAG}" "${PKG_DIR}"

echo "==> stage offline fleet rollout bundle"
EDR_ROLLOUT_PACKAGE_DIR="${PKG_DIR}" bash "${ROOT}/scripts/pilot/stage_fleet_rollout_bundle.sh" "${OUT}"

echo "fleet rollout bundle ready: ${OUT}"
