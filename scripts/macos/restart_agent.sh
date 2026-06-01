#!/usr/bin/env bash
set -euo pipefail

restart_edr_agent() {
	local plist="/Library/LaunchDaemons/com.razatech.edr-agent.plist"
	launchctl bootout system "${plist}" 2>/dev/null || true
	launchctl unload "${plist}" 2>/dev/null || true
	launchctl bootstrap system "${plist}" 2>/dev/null || launchctl load "${plist}"
	launchctl enable "system/com.razatech.edr-agent" 2>/dev/null || true
	launchctl kickstart -k "system/com.razatech.edr-agent" 2>/dev/null || true
}
