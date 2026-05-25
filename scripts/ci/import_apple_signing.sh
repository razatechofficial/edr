#!/usr/bin/env bash
# Import Developer ID certificate(s) into a temporary CI keychain.
#
# Required secrets (either one combined p12 or two separate exports):
#   APPLE_CERTIFICATE_P12              base64 .p12 with Developer ID Application (+ key)
#   APPLE_CERTIFICATE_PASSWORD         password for Application p12
# Optional second export when Application and Installer are separate files:
#   APPLE_INSTALLER_CERTIFICATE_P12    base64 .p12 with Developer ID Installer (+ key)
#   APPLE_INSTALLER_CERTIFICATE_PASSWORD  password (defaults to APPLE_CERTIFICATE_PASSWORD)
#
# Optional identity verification:
#   APPLE_SIGN_IDENTITY / APPLE_INSTALLER_SIGN_IDENTITY
set -euo pipefail

import_p12() {
	local b64="$1"
	local pass="$2"
	local label="$3"
	local dest="$4"
	printf '%s' "${b64}" | tr -d ' \t\r\n' | base64 --decode >"${dest}"
	if [[ ! -s "${dest}" ]]; then
		echo "ERROR: ${label} decoded to an empty file; check base64 secret" >&2
		return 1
	fi
	echo "Decoded ${label} size: $(wc -c <"${dest}") bytes"
	local out
	out="$(security import "${dest}" -k "${KEYCHAIN}" -P "${pass}" \
		-T /usr/bin/codesign -T /usr/bin/productsign -T /usr/bin/security 2>&1)" || {
		echo "${out}" >&2
		if grep -qi 'MAC verification failed\|wrong password' <<<"${out}"; then
			echo "ERROR: password wrong for ${label}" >&2
		fi
		return 1
	}
	echo "${out}"
}

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
APP_P12="${RUNNER_TEMP:-/tmp}/edr-application.p12"
INSTALLER_P12="${RUNNER_TEMP:-/tmp}/edr-installer.p12"
INSTALLER_PASS="${APPLE_INSTALLER_CERTIFICATE_PASSWORD:-${APPLE_CERTIFICATE_PASSWORD}}"

rm -f "${KEYCHAIN}" "${APP_P12}" "${INSTALLER_P12}" 2>/dev/null || true
security create-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN}"
security set-keychain-settings -lut 21600 "${KEYCHAIN}"
security unlock-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN}"

import_p12 "${APPLE_CERTIFICATE_P12}" "${APPLE_CERTIFICATE_PASSWORD}" "Application p12" "${APP_P12}"

if [[ -n "${APPLE_INSTALLER_CERTIFICATE_P12:-}" ]]; then
	import_p12 "${APPLE_INSTALLER_CERTIFICATE_P12}" "${INSTALLER_PASS}" "Installer p12" "${INSTALLER_P12}"
fi
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
		echo "Export Developer ID Application (+ private key) to APPLE_CERTIFICATE_P12." >&2
		exit 1
	fi
fi

if [[ -n "${APPLE_INSTALLER_SIGN_IDENTITY:-}" ]]; then
	if ! grep -Fq "Developer ID Installer:" <<<"${INSTALLER_IDS}" && \
		! grep -Fq "${APPLE_INSTALLER_SIGN_IDENTITY}" <<<"${INSTALLER_IDS}" && \
		! grep -Fq "${APPLE_INSTALLER_SIGN_IDENTITY}" <<<"${CODESIGN_IDS}"; then
		echo "ERROR: APPLE_INSTALLER_SIGN_IDENTITY not found after import: ${APPLE_INSTALLER_SIGN_IDENTITY}" >&2
		echo "Export Developer ID Installer (+ private key) to APPLE_INSTALLER_CERTIFICATE_P12," >&2
		echo "or combine Application + Installer in one p12 export." >&2
		exit 1
	fi
fi
