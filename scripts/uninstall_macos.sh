#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "run as root: sudo $0" >&2
	exit 1
fi

KEEP_DATA="${KEEP_DATA:-0}"
INSTALLER=""
for c in /usr/local/bin/edr-installer /Library/Application\ Support/EDR/bin/edr-installer; do
	if [[ -x "$c" ]]; then
		INSTALLER="$c"
		break
	fi
done

if [[ -n "${INSTALLER}" ]]; then
	if [[ "${KEEP_DATA}" == "1" ]]; then
		"${INSTALLER}" uninstall --keep-data
	else
		"${INSTALLER}" uninstall
	fi
	exit 0
fi

PLIST="/Library/LaunchDaemons/com.razatech.edr-agent.plist"
if launchctl print "system/com.razatech.edr-agent" &>/dev/null; then
	launchctl bootout system "${PLIST}" 2>/dev/null || true
fi
launchctl unload "${PLIST}" 2>/dev/null || true
rm -f "${PLIST}"

UI_PLIST="/Library/LaunchAgents/com.razatech.edr-agent-ui.plist"
CONSOLE_USER="$(stat -f '%Su' /dev/console 2>/dev/null || true)"
if [[ -n "${CONSOLE_USER}" && "${CONSOLE_USER}" != "root" && "${CONSOLE_USER}" != "loginwindow" ]]; then
	UID_U="$(id -u "${CONSOLE_USER}" 2>/dev/null || true)"
	if [[ -n "${UID_U}" ]]; then
		launchctl bootout "gui/${UID_U}/com.razatech.edr-agent-ui" 2>/dev/null || true
		launchctl bootout "gui/${UID_U}/com.razatech.edr.firstrun" 2>/dev/null || true
	fi
	sudo -u "${CONSOLE_USER}" security delete-generic-password -s "com.razatech.edr.xdr-identity" 2>/dev/null || true
fi
rm -f "${UI_PLIST}"
rm -f /Library/LaunchAgents/com.razatech.edr.firstrun.plist

rm -f /usr/local/bin/edr-agent /usr/local/bin/edrctl /usr/local/bin/edr /usr/local/bin/edr-installer /usr/local/bin/edr-agent-ui
rm -rf "/Applications/EDR Agent.app"

if [[ "${KEEP_DATA}" != "1" ]]; then
	rm -rf "/Library/Application Support/EDR"
	rm -rf /Library/Logs/EDR
	echo "Removed LaunchDaemon, login items, binaries, rules, models, certs, and data."
else
	echo "Removed LaunchDaemon and binaries. Data under /Library/Application Support/EDR/ was kept."
fi
