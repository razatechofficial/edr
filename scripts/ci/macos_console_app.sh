#!/usr/bin/env bash
# Assemble /Applications/EDR Agent.app as a real macOS applet (osacompile)
# so Launchpad, Spotlight, and Finder can open it. Falls back to the Go UI
# binary only when osacompile is unavailable.
# Usage: macos_console_app.sh <ui-binary> <edrctl-binary> <dest.app>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UI_BIN="${1:-}"
CTL_BIN="${2:-}"
APP_OUT="${3:-}"
SCRIPT="${ROOT}/build/macos/console.applescript"
INFO_PLIST="${ROOT}/build/macos/Info-console.plist"

if [[ -z "${APP_OUT}" ]]; then
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

sign_target() {
	local path="$1"
	# Do not use hardened runtime on the console applet: it breaks
	# AppleScript "do shell script" / administrator-privileges dialogs.
	if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
		codesign --force --timestamp --sign "${APPLE_SIGN_IDENTITY}" "${path}"
	else
		codesign --force --sign - "${path}" || true
	fi
}

rm -rf "${APP_OUT}"
mkdir -p "$(dirname "${APP_OUT}")"

if command -v osacompile >/dev/null 2>&1 && [[ -f "${SCRIPT}" ]]; then
	osacompile -o "${APP_OUT}" "${SCRIPT}"
	PLIST="${APP_OUT}/Contents/Info.plist"
	plutil -replace CFBundleName -string "EDR Agent" "${PLIST}" >/dev/null
	plutil -replace CFBundleDisplayName -string "EDR Agent" "${PLIST}" >/dev/null
	plutil -replace CFBundleIdentifier -string "com.razatech.edr.console" "${PLIST}" >/dev/null
	plutil -replace LSApplicationCategoryType -string "public.app-category.utilities" "${PLIST}" >/dev/null 2>&1 || true
	plutil -replace NSHighResolutionCapable -bool true "${PLIST}" >/dev/null 2>&1 || true
	mkdir -p "${APP_OUT}/Contents/MacOS"
	if [[ -n "${CTL_BIN}" && -f "${CTL_BIN}" ]]; then
		cp "${CTL_BIN}" "${APP_OUT}/Contents/MacOS/edrctl"
		chmod 755 "${APP_OUT}/Contents/MacOS/edrctl"
		sign_target "${APP_OUT}/Contents/MacOS/edrctl"
	fi
	if [[ -n "${UI_BIN}" && -f "${UI_BIN}" ]]; then
		cp "${UI_BIN}" "${APP_OUT}/Contents/MacOS/edr-agent-ui"
		chmod 755 "${APP_OUT}/Contents/MacOS/edr-agent-ui"
		sign_target "${APP_OUT}/Contents/MacOS/edr-agent-ui"
	fi
	if [[ -x "${APP_OUT}/Contents/MacOS/applet" ]]; then
		sign_target "${APP_OUT}/Contents/MacOS/applet"
	fi
	sign_target "${APP_OUT}"
	echo "Console applet: ${APP_OUT}"
	exit 0
fi

if [[ -z "${UI_BIN}" || ! -f "${UI_BIN}" ]]; then
	echo "osacompile unavailable and UI binary missing: ${UI_BIN:-}" >&2
	exit 1
fi

mkdir -p "${APP_OUT}/Contents/MacOS"
cp "${UI_BIN}" "${APP_OUT}/Contents/MacOS/edr-agent-ui"
chmod 755 "${APP_OUT}/Contents/MacOS/edr-agent-ui"
if [[ -n "${CTL_BIN}" && -f "${CTL_BIN}" ]]; then
	cp "${CTL_BIN}" "${APP_OUT}/Contents/MacOS/edrctl"
	chmod 755 "${APP_OUT}/Contents/MacOS/edrctl"
fi
cp "${INFO_PLIST}" "${APP_OUT}/Contents/Info.plist"
printf 'APPL????' > "${APP_OUT}/Contents/PkgInfo"
sign_target "${APP_OUT}/Contents/MacOS/edr-agent-ui"
if [[ -f "${APP_OUT}/Contents/MacOS/edrctl" ]]; then
	sign_target "${APP_OUT}/Contents/MacOS/edrctl"
fi
sign_target "${APP_OUT}"
echo "Console app (Go fallback): ${APP_OUT}"
