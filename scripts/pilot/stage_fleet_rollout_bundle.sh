#!/usr/bin/env bash
# Stage packages, TLS material, and pilot scripts for offline/airgap fleet rollout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-${ROOT}/dist/fleet-rollout-bundle}"
TLS_SRC="${EDR_CONTROLPLANE_TLS_DIR:-/etc/edr-controlplane/tls}"
PKG_SRC="${EDR_ROLLOUT_PACKAGE_DIR:-${ROOT}/dist/release}"

rm -rf "${OUT}"
mkdir -p "${OUT}/packages" "${OUT}/tls" "${OUT}/scripts/pilot" "${OUT}/scripts/deploy" "${OUT}/scripts/linux" "${OUT}/scripts/macos" "${OUT}/scripts/windows"

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
	scripts/pilot/run_rollout_validation.sh \
	scripts/pilot/upgrade_linux_agent.sh \
	scripts/pilot/upgrade_macos_agent.sh \
	scripts/deploy/backup_controlplane.sh \
	scripts/deploy/restore_controlplane.sh \
	scripts/deploy/copy_agent_tls.sh \
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

cat > "${OUT}/ROLLOUT.txt" <<'TXT'
Offline fleet rollout bundle

Contents:
  packages/   Linux .deb/.rpm, macOS .pkg, Windows .msi
  tls/        Control plane CA + agent client cert (mTLS)
  scripts/    Pilot apply + verify helpers

Control plane host (already deployed):
  export EDR_CONTROLPLANE_HTTPS=1
  export EDR_CONTROLPLANE_API_TOKEN=<from /etc/edr-controlplane/env>
  bash scripts/pilot/rollout_status.sh <cp-host> <expected-agents>
  bash scripts/pilot/run_rollout_validation.sh <cp-host> <expected-agents>

Linux endpoint:
  sudo dpkg -i packages/edr-agent_*_amd64.deb
  sudo scripts/deploy/copy_agent_tls.sh tls linux
  sudo scripts/linux/apply_tenant_tls_config.sh <cp-host>
  bash scripts/pilot/verify_linux_tenant.sh <cp-host>

macOS endpoint:
  sudo installer -pkg packages/edr-agent_*.pkg -target /
  sudo scripts/deploy/copy_agent_tls.sh tls macos
  sudo scripts/macos/apply_tenant_tls_config.sh <cp-host>
  bash scripts/pilot/verify_macos_tenant.sh <cp-host>

Windows endpoint (Admin):
  msiexec /i packages\edr-agent_*.msi /qn
  copy tls\*.crt tls\*.key to C:\ProgramData\EDR Agent\tls\
  apply_tenant_tls_config.bat <cp-host>
  powershell -File scripts\pilot\verify_windows_tenant.ps1

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
