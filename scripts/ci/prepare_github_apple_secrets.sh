#!/usr/bin/env bash
# Validate both p12 exports and print GitHub secret update checklist.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_P12="${1:-$HOME/Downloads/DeveloperID.p12}"
INSTALLER_P12="${2:-$HOME/Downloads/DeveloperID-Installer.p12}"

if [[ ! -f "${APP_P12}" ]]; then
	echo "missing Application p12: ${APP_P12}" >&2
	exit 1
fi
if [[ ! -f "${INSTALLER_P12}" ]]; then
	echo "missing Installer p12: ${INSTALLER_P12}" >&2
	echo "Export Developer ID Installer from Keychain Access first." >&2
	exit 1
fi

echo "=== Validating p12 files ==="
bash "${ROOT}/scripts/ci/validate_apple_p12_local.sh" "${APP_P12}" "${INSTALLER_P12}"

echo
echo "=== GitHub secrets checklist ==="
echo "Update these in Settings → Secrets and variables → Actions:"
echo
echo "APPLE_CERTIFICATE_P12"
echo "  (paste output of: base64 -i ${APP_P12} | pbcopy)"
echo
echo "APPLE_INSTALLER_CERTIFICATE_P12"
echo "  (paste output of: base64 -i ${INSTALLER_P12} | pbcopy)"
echo
echo "APPLE_CERTIFICATE_PASSWORD"
echo "  (password used when exporting Application.p12)"
echo
echo "APPLE_INSTALLER_CERTIFICATE_PASSWORD  (optional if same password)"
echo
echo "File sizes (sanity check):"
wc -c "${APP_P12}" "${INSTALLER_P12}"
