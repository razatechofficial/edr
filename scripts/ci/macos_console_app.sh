#!/usr/bin/env bash
# Assemble the operator GUI as /Applications-style EDR Agent.app.
# Usage: macos_console_app.sh <ui-binary> <edrctl-binary> <dest.app>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UI_BIN="${1:-}"
CTL_BIN="${2:-}"
APP_OUT="${3:-}"

if [[ -z "${UI_BIN}" || ! -f "${UI_BIN}" || -z "${APP_OUT}" ]]; then
	echo "usage: macos_console_app.sh path/to/edr-agent-ui path/to/edrctl dest/EDR Agent.app" >&2
	exit 1
fi

if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
	_keychain_search=()
	if [[ -n "${KEYCHAIN_PATH:-}" ]]; then
		_keychain_search=("${KEYCHAIN_PATH}")
	fi
	if ! security find-identity -v -p codesigning "${_keychain_search[@]}" 2>/dev/null | grep -Fq "${APPLE_SIGN_IDENTITY}"; then
		echo "APPLE_SIGN_IDENTITY not present in keychain; ad-hoc signing console app" >&2
		APPLE_SIGN_IDENTITY=""
	fi
fi

INFO_PLIST="${ROOT}/build/macos/Info-console.plist"
rm -rf "${APP_OUT}"
mkdir -p "${APP_OUT}/Contents/MacOS"
cp "${UI_BIN}" "${APP_OUT}/Contents/MacOS/edr-agent-ui"
chmod 755 "${APP_OUT}/Contents/MacOS/edr-agent-ui"
if [[ -n "${CTL_BIN}" && -f "${CTL_BIN}" ]]; then
	cp "${CTL_BIN}" "${APP_OUT}/Contents/MacOS/edrctl"
	chmod 755 "${APP_OUT}/Contents/MacOS/edrctl"
fi
cp "${INFO_PLIST}" "${APP_OUT}/Contents/Info.plist"
printf 'APPL????' > "${APP_OUT}/Contents/PkgInfo"

sign_target() {
	local path="$1"
	if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
		codesign --force --options runtime --timestamp --sign "${APPLE_SIGN_IDENTITY}" "${path}"
	else
		codesign --force --sign - "${path}" || true
	fi
}

sign_target "${APP_OUT}/Contents/MacOS/edr-agent-ui"
if [[ -f "${APP_OUT}/Contents/MacOS/edrctl" ]]; then
	sign_target "${APP_OUT}/Contents/MacOS/edrctl"
fi
sign_target "${APP_OUT}"
echo "Console app: ${APP_OUT}"
