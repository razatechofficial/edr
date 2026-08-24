#!/usr/bin/env bash
# Assemble /Applications/EDR Agent.app from the arch-specific Go UI binary.
# Do not wrap with a universal AppleScript applet: that opens on the wrong CPU
# and then execs edrctl of a different architecture (Bad CPU type).
# Usage: macos_console_app.sh <ui-binary> <edrctl-binary> <dest.app>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UI_BIN="${1:-}"
APP_OUT="${3:-}"
INFO_PLIST="${ROOT}/build/macos/Info-console.plist"
ENTITLEMENTS="${ROOT}/build/macos/edr-console.entitlements.plist"

if [[ -z "${UI_BIN}" || ! -f "${UI_BIN}" || -z "${APP_OUT}" ]]; then
	echo "usage: macos_console_app.sh path/to/edr-agent-ui path/to/edrctl dest/EDR Agent.app" >&2
	exit 1
fi

if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
	ids=""
	if [[ -n "${KEYCHAIN_PATH:-}" ]]; then
		ids="$(security find-identity -v -p codesigning "${KEYCHAIN_PATH}" 2>/dev/null || true)"
	else
		ids="$(security find-identity -v -p codesigning 2>/dev/null || true)"
	fi
	if ! grep -Fq "${APPLE_SIGN_IDENTITY}" <<<"${ids}"; then
		echo "APPLE_SIGN_IDENTITY not present in keychain; ad-hoc signing console app" >&2
		APPLE_SIGN_IDENTITY=""
	fi
fi

sign_target() {
	local path="$1"
	shift || true
	if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
		if [[ $# -gt 0 ]]; then
			codesign --force --options runtime --timestamp \
				"$@" \
				--sign "${APPLE_SIGN_IDENTITY}" "${path}"
		else
			codesign --force --options runtime --timestamp \
				--sign "${APPLE_SIGN_IDENTITY}" "${path}"
		fi
	else
		codesign --force --sign - "${path}" || true
	fi
}

rm -rf "${APP_OUT}"
mkdir -p "${APP_OUT}/Contents/MacOS"
cp "${UI_BIN}" "${APP_OUT}/Contents/MacOS/edr-agent-ui"
chmod 755 "${APP_OUT}/Contents/MacOS/edr-agent-ui"
cp "${INFO_PLIST}" "${APP_OUT}/Contents/Info.plist"
printf 'APPL????' > "${APP_OUT}/Contents/PkgInfo"
sign_target "${APP_OUT}/Contents/MacOS/edr-agent-ui"
if [[ -f "${ENTITLEMENTS}" ]]; then
	sign_target "${APP_OUT}" --entitlements "${ENTITLEMENTS}"
else
	sign_target "${APP_OUT}"
fi
echo "Console app: ${APP_OUT}"
