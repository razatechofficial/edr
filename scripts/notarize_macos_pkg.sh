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

if [[ -n "${SIGN_IDENTITY:-}" ]]; then
	echo "==> Signing with productsign (${SIGN_IDENTITY})"
	TMP="${PKG}.tmp-signed"
	productsign --sign "${SIGN_IDENTITY}" "${PKG}" "${TMP}"
	mv "${TMP}" "${PKG}"
fi

echo "==> Submitting to Apple Notary Service: ${PKG}"

if [[ -n "${NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
	xcrun notarytool submit "${PKG}" --keychain-profile "${NOTARY_KEYCHAIN_PROFILE}" --wait
elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]]; then
	xcrun notarytool submit "${PKG}" \
		--apple-id "${APPLE_ID}" \
		--team-id "${APPLE_TEAM_ID}" \
		--password "${APPLE_APP_SPECIFIC_PASSWORD}" \
		--wait
else
	echo "Set NOTARY_KEYCHAIN_PROFILE or APPLE_ID + APPLE_TEAM_ID + APPLE_APP_SPECIFIC_PASSWORD" >&2
	exit 1
fi

echo "==> Stapling ticket"
xcrun stapler staple "${PKG}"

echo "==> Done (notarized + stapled): ${PKG}"
