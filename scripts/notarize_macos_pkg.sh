#!/usr/bin/env bash
# Notarize and staple a signed macOS .pkg (required for Gatekeeper on modern macOS).
#
# Prerequisites:
#   - Apple Developer Program membership
#   - Installer certificate: "Developer ID Installer: ..." in Keychain (for optional productsign)
#   - App-specific password or notarytool keychain profile (see below)
#
# Usage:
#   ./scripts/notarize_macos_pkg.sh [path/to.pkg]
#   If PKG is omitted, uses the newest dist/*-consumer.pkg
#
# Authentication (pick one):
#   NOTARY_KEYCHAIN_PROFILE=name   # from: xcrun notarytool store-credentials ...
#   OR all of:
#   APPLE_ID=you@example.com
#   APPLE_TEAM_ID=XXXXXXXXXX
#   APPLE_APP_SPECIFIC_PASSWORD=xxxx-xxxx-xxxx-xxxx
#
# Optional (sign before notarize if the pkg is not yet signed):
#   SIGN_IDENTITY="Developer ID Installer: Your Name (TEAMID)"
#
# References:
#   https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

PKG=${1:-}
if [[ -z "${PKG}" ]]; then
	PKG=$(ls -t dist/*-consumer.pkg 2>/dev/null | head -1 || true)
fi
if [[ -z "${PKG}" || ! -f "${PKG}" ]]; then
	echo "usage: $0 path/to.pkg" >&2
	echo "  or place a consumer pkg under dist/ and run with no args" >&2
	exit 1
fi

if [[ -z "${SIGN_IDENTITY:-}" && -n "${APPLE_INSTALLER_SIGN_IDENTITY:-}" ]]; then
	SIGN_IDENTITY="${APPLE_INSTALLER_SIGN_IDENTITY}"
fi

if [[ -n "${SIGN_IDENTITY:-}" ]]; then
	echo "==> Signing with productsign (${SIGN_IDENTITY})"
	TMP="${PKG}.tmp-signed"
	productsign --sign "${SIGN_IDENTITY}" "${PKG}" "${TMP}"
	mv "${TMP}" "${PKG}"
elif ! pkgutil --check-signature "${PKG}" 2>/dev/null | grep -q "Developer ID Installer"; then
	echo "error: ${PKG} is unsigned; set SIGN_IDENTITY before notarizing" >&2
	echo "  example: SIGN_IDENTITY=\"Developer ID Installer: Your Name (TEAMID)\"" >&2
	exit 1
fi

echo "==> Submitting to Apple Notary Service: ${PKG}"

SUBMIT_JSON="$(mktemp "${TMPDIR:-/tmp}/edr-notary-submit.XXXXXX")"
trap 'rm -f "${SUBMIT_JSON}"' EXIT

if [[ -n "${NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
	xcrun notarytool submit "${PKG}" \
		--keychain-profile "${NOTARY_KEYCHAIN_PROFILE}" \
		--output-format json --wait >"${SUBMIT_JSON}"
elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]]; then
	xcrun notarytool submit "${PKG}" \
		--apple-id "${APPLE_ID}" \
		--team-id "${APPLE_TEAM_ID}" \
		--password "${APPLE_APP_SPECIFIC_PASSWORD}" \
		--output-format json --wait >"${SUBMIT_JSON}"
else
	echo "Set NOTARY_KEYCHAIN_PROFILE or APPLE_ID + APPLE_TEAM_ID + APPLE_APP_SPECIFIC_PASSWORD" >&2
	exit 1
fi

SUBMISSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "${SUBMIT_JSON}")"
NOTARY_STATUS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "${SUBMIT_JSON}")"

if [[ "${NOTARY_STATUS}" != "Accepted" ]]; then
	echo "notarization failed: status=${NOTARY_STATUS} id=${SUBMISSION_ID}" >&2
	LOG_JSON="$(mktemp "${TMPDIR:-/tmp}/edr-notary-log.XXXXXX")"
	if [[ -n "${NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
		xcrun notarytool log "${SUBMISSION_ID}" \
			--keychain-profile "${NOTARY_KEYCHAIN_PROFILE}" >"${LOG_JSON}" 2>/dev/null || true
	elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]]; then
		xcrun notarytool log "${SUBMISSION_ID}" \
			--apple-id "${APPLE_ID}" \
			--team-id "${APPLE_TEAM_ID}" \
			--password "${APPLE_APP_SPECIFIC_PASSWORD}" >"${LOG_JSON}" 2>/dev/null || true
	fi
	if [[ -s "${LOG_JSON}" ]]; then
		echo "==> Apple notarization log (${SUBMISSION_ID})" >&2
		cat "${LOG_JSON}" >&2
	fi
	rm -f "${LOG_JSON}"
	echo "Fetch log manually with:" >&2
	echo "  xcrun notarytool log ${SUBMISSION_ID} --keychain-profile ${NOTARY_KEYCHAIN_PROFILE:-<profile>}" >&2
	exit 1
fi

echo "==> Stapling ticket"
xcrun stapler staple "${PKG}"

echo "==> Done (notarized + stapled): ${PKG}"
