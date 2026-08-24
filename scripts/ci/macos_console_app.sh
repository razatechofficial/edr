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
ENTITLEMENTS="${ROOT}/build/macos/edr-console.entitlements.plist"

if [[ -z "${APP_OUT}" ]]; then
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
		if [[ -f "${ENTITLEMENTS}" ]]; then
			sign_target "${APP_OUT}/Contents/MacOS/applet" --entitlements "${ENTITLEMENTS}"
		else
			sign_target "${APP_OUT}/Contents/MacOS/applet"
		fi
	fi
	if [[ -f "${ENTITLEMENTS}" ]]; then
		sign_target "${APP_OUT}" --entitlements "${ENTITLEMENTS}"
	else
		sign_target "${APP_OUT}"
	fi
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
if [[ -f "${ENTITLEMENTS}" ]]; then
	sign_target "${APP_OUT}" --entitlements "${ENTITLEMENTS}"
else
	sign_target "${APP_OUT}"
fi
echo "Console app (Go fallback): ${APP_OUT}"
