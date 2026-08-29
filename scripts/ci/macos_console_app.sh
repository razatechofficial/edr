#!/usr/bin/env bash
# Assemble /Applications/EDR Agent.app from the arch-specific Go UI binary.
# Do not wrap with a universal AppleScript applet: that opens on the wrong CPU
# and then execs edrctl of a different architecture (Bad CPU type).
# Usage: macos_console_app.sh <ui-binary> <edrctl-binary> <dest.app> [installer]
# The optional installer (prefer embedbundle) lives next to the UI so Accept
# can copy the sensor without a zip of loose binaries.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UI_BIN="${1:-}"
CTL_BIN="${2:-}"
APP_OUT="${3:-}"
INSTALLER_BIN="${4:-${INSTALLER_BIN:-}}"
INFO_PLIST="${ROOT}/build/macos/Info-console.plist"
ENTITLEMENTS="${ROOT}/build/macos/edr-console.entitlements.plist"

if [[ -z "${UI_BIN}" || ! -f "${UI_BIN}" || -z "${APP_OUT}" ]]; then
	echo "usage: macos_console_app.sh path/to/edr-agent-ui path/to/edrctl dest/EDR Agent.app [installer]" >&2
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

if command -v otool >/dev/null 2>&1 && otool -L "${UI_BIN}" | grep -Eiq 'libyara|/opt/yara/|/Cellar/yara/'; then
	echo "${UI_BIN} links Homebrew libyara; rebuild the console without CGO yara flags" >&2
	otool -L "${UI_BIN}" >&2 || true
	exit 1
fi

rm -rf "${APP_OUT}"
mkdir -p "${APP_OUT}/Contents/MacOS"
cp "${UI_BIN}" "${APP_OUT}/Contents/MacOS/edr-agent-ui"
chmod 755 "${APP_OUT}/Contents/MacOS/edr-agent-ui"
if [[ -n "${CTL_BIN}" && -f "${CTL_BIN}" ]]; then
	cp "${CTL_BIN}" "${APP_OUT}/Contents/MacOS/edrctl"
	chmod 755 "${APP_OUT}/Contents/MacOS/edrctl"
	sign_target "${APP_OUT}/Contents/MacOS/edrctl"
fi
if [[ -n "${INSTALLER_BIN}" && -f "${INSTALLER_BIN}" ]]; then
	cp "${INSTALLER_BIN}" "${APP_OUT}/Contents/MacOS/edr-installer"
	chmod 755 "${APP_OUT}/Contents/MacOS/edr-installer"
	sign_target "${APP_OUT}/Contents/MacOS/edr-installer"
fi
cp "${INFO_PLIST}" "${APP_OUT}/Contents/Info.plist"
printf 'APPL????' > "${APP_OUT}/Contents/PkgInfo"
sign_target "${APP_OUT}/Contents/MacOS/edr-agent-ui"
if [[ -f "${ENTITLEMENTS}" ]]; then
	sign_target "${APP_OUT}" --entitlements "${ENTITLEMENTS}"
else
	sign_target "${APP_OUT}"
fi
echo "Console app: ${APP_OUT}"
