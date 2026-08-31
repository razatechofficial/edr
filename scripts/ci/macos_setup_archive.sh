#!/usr/bin/env bash
# Build the attended macOS download: EDR-Agent-Setup.app inside a zip (and DMG).
# prod CI does not call this. Use the attended-setup branch for the custom wizard.
# Double-click the .app — Fyne wizard, not Apple Installer.app.
# Usage: macos_setup_archive.sh <ui-bin> <edrctl-bin> <installer-bin> <arch>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UI_BIN="${1:-}"
CTL_BIN="${2:-}"
INSTALLER_BIN="${3:-}"
ARCH="${4:-arm64}"

if [[ -z "${UI_BIN}" || ! -f "${UI_BIN}" || -z "${INSTALLER_BIN}" || ! -f "${INSTALLER_BIN}" ]]; then
	echo "usage: $0 path/to/edr-agent-ui path/to/edrctl path/to/edr-installer arch" >&2
	exit 1
fi

case "${ARCH}" in
amd64 | x86_64) LABEL=intel ;;
*) LABEL=apple-silicon ;;
esac

SETUP_APP="${ROOT}/dist/EDR-Agent-Setup.app"
ZIP_OUT="${ROOT}/dist/EDR-Agent-Setup_${LABEL}.zip"
DMG_OUT="${ROOT}/dist/EDR-Agent-Setup_${LABEL}.dmg"

EDR_BUNDLE_ID=com.razatech.edr.setup \
	EDR_DISPLAY_NAME="EDR Agent Setup" \
	bash "${ROOT}/scripts/ci/macos_console_app.sh" \
	"${UI_BIN}" "${CTL_BIN}" "${SETUP_APP}" "${INSTALLER_BIN}"

rm -f "${ZIP_OUT}" "${DMG_OUT}"
# ditto preserves code signatures; `zip` does not.
ditto -c -k --keepParent "${SETUP_APP}" "${ZIP_OUT}"

if command -v hdiutil >/dev/null 2>&1; then
	STAGE="$(mktemp -d "${TMPDIR:-/tmp}/edr-setup-dmg.XXXXXX")"
	ditto "${SETUP_APP}" "${STAGE}/EDR-Agent-Setup.app"
	hdiutil create -volname "EDR Agent Setup" -srcfolder "${STAGE}" \
		-ov -format UDZO "${DMG_OUT}" >/dev/null || true
	rm -rf "${STAGE}"
	if [[ -f "${DMG_OUT}" && -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
		codesign --force --timestamp --sign "${APPLE_SIGN_IDENTITY}" "${DMG_OUT}" || true
	fi
fi

echo "attended setup app: ${SETUP_APP}"
echo "attended setup zip: ${ZIP_OUT}"
echo "attended setup dmg: ${DMG_OUT}"
