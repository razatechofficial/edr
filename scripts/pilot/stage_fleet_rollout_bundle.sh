#!/usr/bin/env bash
# Stage packages, TLS material, and pilot scripts for offline/airgap fleet rollout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-${ROOT}/dist/fleet-rollout-bundle}"
TLS_SRC="${EDR_CONTROLPLANE_TLS_DIR:-/etc/edr-controlplane/tls}"
PKG_SRC="${EDR_ROLLOUT_PACKAGE_DIR:-${ROOT}/dist/release}"

rm -rf "${OUT}"
mkdir -p "${OUT}/packages" "${OUT}/tls" "${OUT}/ioc" "${OUT}/scripts/pilot" "${OUT}/scripts/deploy" "${OUT}/scripts/linux" "${OUT}/scripts/macos" "${OUT}/scripts/windows" "${OUT}/configs/reference"

for ref in configs/agent.gov.yaml configs/agent.airgap.yaml; do
	if [[ -f "${ROOT}/${ref}" ]]; then
		cp "${ROOT}/${ref}" "${OUT}/configs/reference/"
	fi
done

shopt -s nullglob
copied=0
for src in "${PKG_SRC}" "${ROOT}/dist"; do
	[[ -d "${src}" ]] || continue
	for f in "${src}"/*.deb "${src}"/*.rpm "${src}"/*.pkg "${src}"/*.msi; do
		[[ -f "${f}" ]] || continue
		cp "${f}" "${OUT}/packages/"
		copied=$((copied + 1))
	done
done
if [[ "${copied}" -eq 0 ]]; then
	echo "WARNING: no packages found under ${PKG_SRC} or dist/; run make fetch-release-artifacts first" >&2
fi

if [[ -d "${TLS_SRC}" ]]; then
	for f in ca.crt server.crt server.key agent-client.crt agent-client.key; do
		[[ -f "${TLS_SRC}/${f}" ]] && cp "${TLS_SRC}/${f}" "${OUT}/tls/"
	done
else
	echo "WARNING: TLS source missing: ${TLS_SRC}" >&2
fi

if [[ "${EDR_BUNDLE_FETCH_INTEL:-0}" == "1" || "${EDR_BUNDLE_FETCH_INTEL:-0}" == "true" ]]; then
	echo "==> fetching and converting threat intel (requires network)"
	bash "${ROOT}/scripts/update-intel.sh"
elif [[ -x "${ROOT}/scripts/convert-intel.sh" ]]; then
	echo "==> converting offline IOC baseline (no network fetch)"
	bash "${ROOT}/scripts/convert-intel.sh" || echo "WARNING: IOC convert failed; bundle may lack ioc/ files" >&2
fi

for f in hashes.json ips.csv domains.csv kev.json; do
	if [[ -f "${ROOT}/rules/ioc/${f}" ]]; then
		cp "${ROOT}/rules/ioc/${f}" "${OUT}/ioc/"
	fi
done
if [[ ! -f "${OUT}/ioc/hashes.json" ]]; then
	echo "WARNING: no IOC databases under rules/ioc/; run make intel-update on a connected host first" >&2
fi

for script in \
	scripts/pilot/run_prod_rollout.sh \
	scripts/pilot/run_fleet_pilot.sh \
	scripts/pilot/rollout_status.sh \
	scripts/pilot/verify_controlplane.sh \
	scripts/pilot/verify_linux_tenant.sh \
	scripts/pilot/verify_macos_tenant.sh \
	scripts/pilot/verify_installed_agent.sh \
	scripts/pilot/verify_detection_pipeline.sh \
	scripts/pilot/pilot_mtls_check.sh \
	scripts/pilot/run_endpoint_pilot.sh \
	scripts/pilot/check_prod_release.sh \
	scripts/pilot/wait_for_prod_release.sh \
	scripts/pilot/prepare_fleet_rollout.sh \
	scripts/pilot/preflight_rollout.sh \
	scripts/pilot/verify_fleet_rollout.sh \
	scripts/pilot/list_fleet_endpoints.sh \
	scripts/pilot/verify_controlplane_policy.sh \
	scripts/pilot/verify_agent_policy_sync.sh \
	scripts/pilot/verify_policy_sync.sh \
	scripts/pilot/wait_for_policy_sync.sh \
	scripts/pilot/run_policy_pilot.sh \
	scripts/pilot/verify_fleet_policy_rollout.sh \
	scripts/pilot/verify_agent_ioc.sh \
	scripts/pilot/run_rollout_validation.sh \
	scripts/pilot/upgrade_linux_agent.sh \
	scripts/pilot/upgrade_macos_agent.sh \
	scripts/deploy/backup_controlplane.sh \
	scripts/deploy/restore_controlplane.sh \
	scripts/deploy/copy_agent_tls.sh \
	scripts/deploy/distribute_agent_tls.sh \
	scripts/deploy/stage_controlplane_policy.sh \
	scripts/deploy/install_agent_ioc.sh \
	scripts/deploy/export_controlplane_env.sh \
	scripts/linux/apply_tenant_tls_config.sh \
	scripts/macos/apply_tenant_tls_config.sh \
	scripts/windows/apply_tenant_tls_config.bat; do
	if [[ -f "${ROOT}/${script}" ]]; then
		dest="${OUT}/${script}"
		mkdir -p "$(dirname "${dest}")"
		cp "${ROOT}/${script}" "${dest}"
		chmod +x "${dest}" 2>/dev/null || true
	fi
done

if [[ -f "${ROOT}/scripts/pilot/verify_windows_tenant.ps1" ]]; then
	cp "${ROOT}/scripts/pilot/verify_windows_tenant.ps1" "${OUT}/scripts/pilot/"
fi
if [[ -f "${ROOT}/scripts/pilot/verify_detection_pipeline.ps1" ]]; then
	cp "${ROOT}/scripts/pilot/verify_detection_pipeline.ps1" "${OUT}/scripts/pilot/"
fi
if [[ -f "${ROOT}/scripts/pilot/upgrade_windows_agent.ps1" ]]; then
	cp "${ROOT}/scripts/pilot/upgrade_windows_agent.ps1" "${OUT}/scripts/pilot/"
fi
if [[ -f "${ROOT}/scripts/pilot/verify_installed_agent.ps1" ]]; then
	cp "${ROOT}/scripts/pilot/verify_installed_agent.ps1" "${OUT}/scripts/pilot/"
fi
if [[ -f "${ROOT}/scripts/pilot/pilot_fleet_check.sh" ]]; then
	cp "${ROOT}/scripts/pilot/pilot_fleet_check.sh" "${OUT}/scripts/pilot/"
fi
if [[ -f "${ROOT}/scripts/pilot/verify_agent_policy_sync.ps1" ]]; then
	cp "${ROOT}/scripts/pilot/verify_agent_policy_sync.ps1" "${OUT}/scripts/pilot/"
fi
if [[ -f "${ROOT}/scripts/pilot/verify_policy_sync.ps1" ]]; then
	cp "${ROOT}/scripts/pilot/verify_policy_sync.ps1" "${OUT}/scripts/pilot/"
fi

cat > "${OUT}/ROLLOUT.txt" <<'TXT'
Offline fleet rollout bundle

Contents:
  packages/   Linux .deb/.rpm, macOS .pkg, Windows .msi
  tls/        Control plane CA + agent client cert (mTLS)
  ioc/        Offline hash/IP/domain IOC databases (sneakernet)
  scripts/    Pilot apply + verify helpers
  configs/reference/  Government and airgap profile references

Control plane host (already deployed):
  bash scripts/pilot/preflight_rollout.sh <cp-host>
  export EDR_CONTROLPLANE_HTTPS=1
  export EDR_CONTROLPLANE_API_TOKEN=<from /etc/edr-controlplane/env>
  bash scripts/pilot/list_fleet_endpoints.sh <cp-host>
  bash scripts/pilot/verify_fleet_rollout.sh <cp-host> <expected-agents>

Policy bundles (control plane):
  sudo scripts/deploy/stage_controlplane_policy.sh
  sudo systemctl restart edr-controlplane
  bash scripts/pilot/verify_controlplane_policy.sh <cp-host>
  edrctl fleet policy --https --token \$EDR_CONTROLPLANE_API_TOKEN --ca-cert /etc/edr-controlplane/tls/ca.crt

Agent policy sync (endpoint, after CP policy staged):
  bash scripts/pilot/wait_for_policy_sync.sh <cp-host>
  make verify-fleet-policy-rollout HOST=<cp-host> EXPECTED=<expected-agents>

Offline IOC (airgap endpoints, before or after agent install):
  sudo scripts/deploy/install_agent_ioc.sh ioc linux|macos|windows
  bash scripts/pilot/verify_agent_ioc.sh

Remote mTLS distribution (from control plane, over SSH):
  scripts/deploy/distribute_agent_tls.sh tls <agent-host> linux
  EDR_SSH_USER=<user> scripts/deploy/distribute_agent_tls.sh tls <agent-host> macos
  EDR_SSH_USER=Administrator scripts/deploy/distribute_agent_tls.sh tls <agent-host> windows

Linux endpoint:
  sudo dpkg -i packages/edr-agent_*_amd64.deb
  sudo scripts/deploy/install_agent_ioc.sh ioc linux
  sudo scripts/deploy/copy_agent_tls.sh tls linux
  sudo scripts/linux/apply_tenant_tls_config.sh <cp-host>
  bash scripts/pilot/verify_linux_tenant.sh <cp-host>

macOS endpoint:
  sudo installer -pkg packages/edr-agent_*.pkg -target /
  sudo scripts/deploy/install_agent_ioc.sh ioc macos
  sudo scripts/deploy/copy_agent_tls.sh tls macos
  sudo scripts/macos/apply_tenant_tls_config.sh <cp-host>
  bash scripts/pilot/verify_macos_tenant.sh <cp-host>

Windows endpoint (Admin):
  msiexec /i packages\edr-agent_*.msi /qn
  scripts\deploy\install_agent_ioc.sh ioc windows
  copy tls\*.crt tls\*.key to C:\ProgramData\EDR Agent\tls\
  apply_tenant_tls_config.bat <cp-host>
  powershell -File scripts\pilot\verify_windows_tenant.ps1
  "C:\Program Files\EDR Agent\edrctl.exe" --config "%ProgramData%\EDR Agent\config.yml" fleet local

Endpoint pilot (post-install + optional detection):
  EDR_PILOT_VERIFY_DETECTION=1 bash scripts/pilot/run_endpoint_pilot.sh <cp-host>

Upgrade (preserve agent_id/config):
  sudo scripts/pilot/upgrade_linux_agent.sh packages/edr-agent_*_amd64.deb
  sudo scripts/pilot/upgrade_macos_agent.sh packages/edr-agent_*.pkg
  powershell -File scripts\pilot\upgrade_windows_agent.ps1 packages\edr-agent_*.msi

Control plane backup:
  sudo scripts/deploy/backup_controlplane.sh /var/backups/edr-controlplane.tar.gz

Control plane restore:
  sudo EDR_RESTORE_CONFIRM=1 scripts/deploy/restore_controlplane.sh /var/backups/edr-controlplane.tar.gz
TXT

ARCHIVE="${OUT}.tar.gz"
tar -czf "${ARCHIVE}" -C "$(dirname "${OUT}")" "$(basename "${OUT}")"
echo "fleet rollout bundle: ${OUT}"
echo "archive: ${ARCHIVE}"
