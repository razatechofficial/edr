#!/usr/bin/env bash
# Verify release artifacts in dist/ include fleet rollout profiles (post-build smoke).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST="${1:-${ROOT}/dist}"
CHECKED=0

echo "==> verifying release packages under ${DIST}"

shopt -s nullglob
debs=("${DIST}"/edr-agent_*_amd64.deb "${DIST}"/edr-agent_*_arm64.deb)
rpms=("${DIST}"/edr-agent_*.rpm)
pkgs=("${DIST}"/edr-agent_*.pkg)
msis=("${DIST}"/edr-agent_*.msi "${DIST}"/*.msi)

for deb in "${debs[@]}"; do
	[[ -f "${deb}" ]] || continue
	echo "==> Linux deb: $(basename "${deb}")"
	bash "${ROOT}/scripts/verify_linux_package.sh" "${deb}"
	CHECKED=$((CHECKED + 1))
done

for rpm in "${rpms[@]}"; do
	[[ -f "${rpm}" ]] || continue
	if ! command -v rpm2cpio >/dev/null 2>&1; then
		echo "WARNING: skipping rpm verification (rpm2cpio not installed): ${rpm}" >&2
		continue
	fi
	echo "==> Linux rpm: $(basename "${rpm}")"
	tmpdir="$(mktemp -d)"
	(
		cd "${tmpdir}"
		rpm2cpio "${rpm}" | cpio -idm 2>/dev/null
		for p in \
			etc/edr-agent/config.tenant.tls.yml \
			etc/edr-agent/config.fleet.tls.yml \
			usr/bin/edr-agent; do
			if [[ ! -e "${p}" ]]; then
				echo "missing required rpm path: ${p}" >&2
				exit 1
			fi
		done
	)
	rm -rf "${tmpdir}"
	CHECKED=$((CHECKED + 1))
done

for pkg in "${pkgs[@]}"; do
	[[ -f "${pkg}" ]] || continue
	if [[ "$(uname -s)" != "Darwin" ]]; then
		echo "WARNING: skipping macOS pkg verification on $(uname -s): $(basename "${pkg}")" >&2
		continue
	fi
	echo "==> macOS pkg: $(basename "${pkg}")"
	bash "${ROOT}/scripts/verify_macos_pkg.sh" "${pkg}"
	CHECKED=$((CHECKED + 1))
done

for msi in "${msis[@]}"; do
	[[ -f "${msi}" ]] || continue
	case "$(basename "${msi}")" in
	edr-agent*.msi|EDR*.msi) ;;
	*) continue ;;
	esac
	if [[ "$(uname -s)" == "MINGW"* || "$(uname -s)" == "MSYS"* || "${OS:-}" == "Windows_NT" ]]; then
		echo "==> Windows msi: $(basename "${msi}")"
		powershell -NoProfile -ExecutionPolicy Bypass -File "${ROOT}/scripts/ci/verify_windows_msi.ps1" -MsiPath "${msi}"
		CHECKED=$((CHECKED + 1))
	else
		echo "WARNING: skipping MSI verification on $(uname -s): $(basename "${msi}")" >&2
	fi
done

if [[ "${CHECKED}" -eq 0 ]]; then
	echo "ERROR: no release packages found under ${DIST}" >&2
	echo "  build first: make build-linux && bash build/linux/package.sh <version> amd64" >&2
	exit 1
fi

echo "release package verification passed (${CHECKED} artifact(s))"
