#!/usr/bin/env bash
# Validate Developer ID p12 file(s) before uploading to GitHub secrets.
# Usage:
#   bash scripts/ci/validate_apple_p12_local.sh ~/Downloads/DeveloperID.p12
#   bash scripts/ci/validate_apple_p12_local.sh ~/Downloads/Application.p12 ~/Downloads/Installer.p12
set -euo pipefail

APP_P12="${1:-$HOME/Downloads/DeveloperID.p12}"
INSTALLER_P12="${2:-}"
APP_ID="${APPLE_SIGN_IDENTITY:-Developer ID Application: Salman Mahmood (4ZTTWG37MQ)}"
INSTALLER_ID="${APPLE_INSTALLER_SIGN_IDENTITY:-Developer ID Installer: Salman Mahmood (4ZTTWG37MQ)}"

if [[ ! -f "${APP_P12}" ]]; then
	echo "missing file: ${APP_P12}" >&2
	exit 1
fi

read -s -p "Application p12 password: " APP_PASS
echo
INSTALLER_PASS="${APP_PASS}"
if [[ -n "${INSTALLER_P12}" ]]; then
	read -s -p "Installer p12 password: " INSTALLER_PASS
	echo
fi

KEYCHAIN=$(mktemp -u /tmp/edr-validate.XXXXXX).keychain-db
cleanup() { security delete-keychain "${KEYCHAIN}" 2>/dev/null || true; }
trap cleanup EXIT

security create-keychain -p test "${KEYCHAIN}"
security unlock-keychain -p test "${KEYCHAIN}"
security import "${APP_P12}" -k "${KEYCHAIN}" -P "${APP_PASS}" \
	-T /usr/bin/codesign -T /usr/bin/productsign
if [[ -n "${INSTALLER_P12}" ]]; then
	[[ -f "${INSTALLER_P12}" ]] || { echo "missing file: ${INSTALLER_P12}" >&2; exit 1; }
	security import "${INSTALLER_P12}" -k "${KEYCHAIN}" -P "${INSTALLER_PASS}" \
		-T /usr/bin/codesign -T /usr/bin/productsign
fi
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k test "${KEYCHAIN}" 2>/dev/null || true

echo "=== codesigning (need Developer ID Application) ==="
CODESIGN_IDS="$(security find-identity -v -p codesigning "${KEYCHAIN}")"
echo "${CODESIGN_IDS}"
echo "=== basic (need Developer ID Installer) ==="
INSTALLER_IDS="$(security find-identity -v -p basic "${KEYCHAIN}")"
echo "${INSTALLER_IDS}"

ok=0
if grep -Fq "${APP_ID}" <<<"${CODESIGN_IDS}"; then
	echo "OK: Application identity found"
else
	echo "FAIL: missing ${APP_ID}" >&2
	ok=1
fi
if grep -Fq "${INSTALLER_ID}" <<<"${INSTALLER_IDS}" || grep -Fq "${INSTALLER_ID}" <<<"${CODESIGN_IDS}"; then
	echo "OK: Installer identity found"
else
	echo "FAIL: missing ${INSTALLER_ID}" >&2
	ok=1
fi

if [[ "${ok}" -eq 0 ]]; then
	echo
	echo "Ready for GitHub secrets:"
	echo "  base64 -i ${APP_P12} | pbcopy   # -> APPLE_CERTIFICATE_P12"
	if [[ -n "${INSTALLER_P12}" ]]; then
		echo "  base64 -i ${INSTALLER_P12} | pbcopy   # -> APPLE_INSTALLER_CERTIFICATE_P12"
	fi
	echo "  export password(s)            # -> APPLE_CERTIFICATE_PASSWORD"
fi
exit "${ok}"
