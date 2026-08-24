#!/bin/bash
# First-run wizard: macOS cannot grant TCC programmatically (same as CrowdStrike/SentinelOne).
# The agent will not stay running until Full Disk Access is granted.
set -euo pipefail

MODE="${1:-}"
MARKER_DIR="${HOME}/Library/Application Support/EDR"
MARKER="${MARKER_DIR}/.permissions_wizard_done"
LOG="${MARKER_DIR}/first-run.log"
mkdir -p "${MARKER_DIR}"
exec >>"${LOG}" 2>&1
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) first-run-permissions MODE=${MODE}"

has_fda() {
	# Root still needs Full Disk Access to read TCC.db on modern macOS.
	[ -r "/Library/Application Support/com.apple.TCC/TCC.db" ]
}

open_privacy_panes() {
	open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || \
		open "/System/Library/PreferencePanes/Security.prefPane" 2>/dev/null || true
	sleep 1
	open "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent" 2>/dev/null || true
	open "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_ListenEvent" 2>/dev/null || true
}

if has_fda && [[ "${MODE}" != "--force" ]]; then
	touch "${MARKER}"
	echo "Full Disk Access already granted"
	exit 0
fi

if [[ "${MODE}" == "--login" ]]; then
	sleep 3
fi

BTN="Open Settings"
if command -v osascript >/dev/null 2>&1; then
	BTN=$(osascript <<'APPLESCRIPT' 2>/dev/null || echo "Open Settings")
try
	set r to display dialog "EDR Agent cannot start until macOS permissions are granted:

• Full Disk Access (required)
• Input Monitoring (Endpoint Security)
• Notifications (optional)

These cannot be granted silently. Click Open Settings, enable EDR Agent, then quit and reopen this app." with title "EDR Agent — required permissions" buttons {"Quit", "Open Settings"} default button "Open Settings" giving up after 180
	return button returned of r
on error
	return "Quit"
end try
APPLESCRIPT
)
fi

if [[ "${BTN}" == "Open Settings" ]]; then
	open_privacy_panes
	# Wait for the user to grant FDA (up to ~10 minutes).
	for _ in $(seq 1 120); do
		if has_fda; then
			touch "${MARKER}"
			echo "Full Disk Access granted"
			osascript -e 'display notification "EDR Agent permissions granted. The sensor will start." with title "EDR Agent"' 2>/dev/null || true
			exit 0
		fi
		sleep 5
	done
	echo "Full Disk Access not granted within wait window"
	exit 1
fi

echo "user dismissed permission wizard"
exit 1
