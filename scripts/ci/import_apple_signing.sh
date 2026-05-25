#!/usr/bin/env bash
# Import Developer ID certificate(s) into a temporary CI keychain.
#
# Required secrets:
#   APPLE_CERTIFICATE_P12        base64-encoded .p12 export (Application + Installer keys)
#   APPLE_CERTIFICATE_PASSWORD   export password for the .p12
#
# Optional:
#   APPLE_SIGN_IDENTITY / APPLE_INSTALLER_SIGN_IDENTITY (verified after import)
set -euo pipefail

if [[ -z "${APPLE_CERTIFICATE_P12:-}" ]]; then
	echo "APPLE_CERTIFICATE_P12 not set; skipping signing cert import (ad-hoc build)" >&2
	exit 0
fi
if [[ -z "${APPLE_CERTIFICATE_PASSWORD:-}" ]]; then
	echo "APPLE_CERTIFICATE_PASSWORD is required when APPLE_CERTIFICATE_P12 is set" >&2
	exit 1
fi

KEYCHAIN="${RUNNER_TEMP:-/tmp}/edr-signing.keychain-db"
KEYCHAIN_PASSWORD="${APPLE_KEYCHAIN_PASSWORD:-$(openssl rand -base64 32)}"
P12_PATH="${RUNNER_TEMP:-/tmp}/edr-signing.p12"

rm -f "${KEYCHAIN}" "${P12_PATH}-db" 2>/dev/null || true
security create-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN}"
security set-keychain-settings -lut 21600 "${KEYCHAIN}"
security unlock-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN}"

printf '%s' "${APPLE_CERTIFICATE_P12}" | base64 --decode >"${P12_PATH}"
security import "${P12_PATH}" -k "${KEYCHAIN}" -P "${APPLE_CERTIFICATE_PASSWORD}" \
	-T /usr/bin/codesign -T /usr/bin/productsign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "${KEYCHAIN_PASSWORD}" "${KEYCHAIN}" || true

# Prefer our temp keychain for codesign/productsign on this job.
existing="$(security list-keychains -d user | tr -d '"')"
security list-keychains -d user -s "${KEYCHAIN}" ${existing}

if [[ -n "${GITHUB_ENV:-}" ]]; then
	echo "KEYCHAIN_PATH=${KEYCHAIN}" >>"${GITHUB_ENV}"
fi

echo "Imported Apple signing certificate(s) into ${KEYCHAIN}"
echo "=== codesigning identities (Developer ID Application) ==="
CODESIGN_IDS="$(security find-identity -v -p codesigning "${KEYCHAIN}" 2>/dev/null || true)"
echo "${CODESIGN_IDS}"
echo "=== basic identities (Developer ID Installer) ==="
INSTALLER_IDS="$(security find-identity -v -p basic "${KEYCHAIN}" 2>/dev/null || true)"
echo "${INSTALLER_IDS}"

if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
	if ! grep -Fq "${APPLE_SIGN_IDENTITY}" <<<"${CODESIGN_IDS}"; then
		echo "ERROR: APPLE_SIGN_IDENTITY not found after import: ${APPLE_SIGN_IDENTITY}" >&2
		echo "The .p12 likely contains only the Installer cert. Re-export from Keychain Access with BOTH:" >&2
		echo "  - Developer ID Application: ... (private key included)" >&2
		echo "  - Developer ID Installer: ... (private key included)" >&2
		echo "Then update APPLE_CERTIFICATE_P12 (base64) and APPLE_CERTIFICATE_PASSWORD in GitHub secrets." >&2
		exit 1
	fi
fi

if [[ -n "${APPLE_INSTALLER_SIGN_IDENTITY:-}" ]]; then
	if ! grep -Fq "${APPLE_INSTALLER_SIGN_IDENTITY}" <<<"${INSTALLER_IDS}" && ! grep -Fq "${APPLE_INSTALLER_SIGN_IDENTITY}" <<<"${CODESIGN_IDS}"; then
		echo "ERROR: APPLE_INSTALLER_SIGN_IDENTITY not found after import: ${APPLE_INSTALLER_SIGN_IDENTITY}" >&2
		exit 1
	fi
fi
