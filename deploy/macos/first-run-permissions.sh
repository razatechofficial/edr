#!/bin/bash
# First-run wizard: guides the user through macOS Privacy & Security (TCC).
# Cannot grant permissions programmatically — same limitation as commercial antivirus.
#
# Invoked by:
#   - postinstall (sudo -u console user)
#   - LaunchAgent at login (--login)
#
set -euo pipefail

MODE="${1:-}"
MARKER_DIR="${HOME}/Library/Application Support/EDR"
MARKER="${MARKER_DIR}/.permissions_wizard_done"
LOG="${MARKER_DIR}/first-run.log"
mkdir -p "${MARKER_DIR}"
exec >>"${LOG}" 2>&1
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) first-run-permissions MODE=${MODE}"

if [[ -f "${MARKER}" && "${MODE}" != "--force" ]]; then
	echo "marker exists, skipping wizard"
	exit 0
fi

if [[ "${MODE}" == "--login" ]]; then
	sleep 3
fi

BTN="Later"
if command -v osascript >/dev/null 2>&1; then
	BTN=$(osascript <<'APPLESCRIPT' 2>/dev/null || echo "Later")
try
	set r to display dialog "EDR needs Full Disk Access and related permissions for full protection. macOS cannot grant these automatically — enable EDR in System Settings → Privacy & Security." with title "EDR — first run" buttons {"Later", "Open Settings"} default button "Open Settings" giving up after 120
	return button returned of r
on error
	return "Later"
end try
APPLESCRIPT
)
fi

if [[ "${BTN}" == "Open Settings" ]]; then
	open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || \
		open "/System/Library/PreferencePanes/Security.prefPane" 2>/dev/null || true
	sleep 1
	open "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent" 2>/dev/null || true
fi

touch "${MARKER}"
echo "wizard completed, marker written"
exit 0
