#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "run as root: sudo $0" >&2
	exit 1
fi

PLIST="/Library/LaunchDaemons/com.razatech.edr-agent.plist"

if launchctl print "system/com.razatech.edr-agent" &>/dev/null; then
	launchctl bootout system "${PLIST}" 2>/dev/null || true
fi
launchctl unload "${PLIST}" 2>/dev/null || true

rm -f "${PLIST}"
rm -f /usr/local/bin/edr-agent /usr/local/bin/edrctl /usr/local/bin/edr
rm -rf "/Applications/EDR Agent.app"
rm -f /Library/LaunchAgents/com.razatech.edr.firstrun.plist

echo "Removed LaunchDaemon and binaries."
echo "Data under /Library/Application Support/EDR/ was not removed; delete it manually if you want a full wipe."
echo "Logs under /Library/Logs/EDR/ were not removed."
