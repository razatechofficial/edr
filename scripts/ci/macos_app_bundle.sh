#!/usr/bin/env bash
# Wrap the agent binary in an app-like bundle so AMFI can read embedded.provisionprofile
# (required for com.apple.developer.endpoint-security.client on Developer ID builds).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARY="${1:-}"
APP_OUT="${2:-dist/edr-agent.app}"

if [[ -z "${BINARY}" || ! -f "${BINARY}" ]]; then
	echo "usage: macos_app_bundle.sh path/to/edr-agent [dist/edr-agent.app]" >&2
	exit 1
fi

INFO_PLIST="${ROOT}/build/macos/Info.plist"
PROVISION="${ROOT}/build/macos/EDR_Agent_Developer_ID.provisionprofile"

rm -rf "${APP_OUT}"
mkdir -p "${APP_OUT}/Contents/MacOS" "${APP_OUT}/Contents/Frameworks"
cp -f "${BINARY}" "${APP_OUT}/Contents/MacOS/edr-agent"
chmod 755 "${APP_OUT}/Contents/MacOS/edr-agent"
cp -f "${INFO_PLIST}" "${APP_OUT}/Contents/Info.plist"
printf 'APPL????' > "${APP_OUT}/Contents/PkgInfo"

if [[ -f "${PROVISION}" ]]; then
	cp -f "${PROVISION}" "${APP_OUT}/Contents/embedded.provisionprofile"
else
	echo "warning: missing ${PROVISION}; ES entitlement signing will fail at runtime" >&2
fi

bash "${ROOT}/scripts/ci/macos_bundle_dylibs.sh" "${APP_OUT}/Contents/MacOS/edr-agent"
echo "App bundle: ${APP_OUT}"
