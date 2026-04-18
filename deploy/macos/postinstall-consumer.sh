#!/bin/bash
# postinstall for consumer .pkg (embedded installer + first-run permission wizard).
# Installed by scripts/package_macos_consumer.sh into the pkg scripts directory.
set -euo pipefail

export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"

# Log to /tmp (always writable) and under EDR logs if that dir exists or can be created.
mkdir -p "/Library/Logs/EDR" 2>/dev/null || true
LOG="/tmp/edr-consumer-install.log"
if [[ -w "/Library/Logs/EDR" ]]; then
	LOG="/Library/Logs/EDR/consumer-install.log"
fi
{
	echo "=== edr consumer postinstall $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
	echo "PATH=${PATH}"
	uname -a || true
} >>"${LOG}" 2>&1

INSTALLER="/usr/local/bin/edr-installer"
FIRSTRUN="/Library/Application Support/EDR/first-run-permissions.sh"
PLIST="/Library/LaunchAgents/com.razatech.edr.firstrun.plist"

log() {
	echo "$@" >>"${LOG}" 2>&1
	echo "$@" 1>&2
}

if [[ ! -x "${INSTALLER}" ]]; then
	log "error: missing or not executable: ${INSTALLER}"
	exit 1
fi

log "==> Running embedded EDR installer (agent + ML models + rules)"
if ! "${INSTALLER}" install >>"${LOG}" 2>&1; then
	log "error: edr-installer install failed (exit $?); see ${LOG}"
	exit 1
fi

chmod 755 "${FIRSTRUN}" 2>/dev/null || true
chown root:wheel "${PLIST}" 2>/dev/null || true
chmod 644 "${PLIST}" 2>/dev/null || true

# Logged-in GUI user (for TCC prompts — must not run wizard as root).
CONSOLE_USER="$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null || true)"
if [[ -n "${CONSOLE_USER}" && "${CONSOLE_USER}" != "root" && "${CONSOLE_USER}" != "loginwindow" ]]; then
	log "==> First-run permission wizard (user=${CONSOLE_USER})"
	/usr/bin/sudo -u "${CONSOLE_USER}" -H /bin/bash "${FIRSTRUN}" >>"${LOG}" 2>&1 || true
	UID_U="$(/usr/bin/id -u "${CONSOLE_USER}" 2>/dev/null || echo "")"
	if [[ -n "${UID_U}" ]]; then
		LC=/usr/bin/launchctl; [[ -x /bin/launchctl ]] && LC=/bin/launchctl
		/usr/bin/sudo -u "${CONSOLE_USER}" "${LC}" bootout "gui/${UID_U}/com.razatech.edr.firstrun" >>"${LOG}" 2>&1 || true
		/usr/bin/sudo -u "${CONSOLE_USER}" "${LC}" bootstrap "gui/${UID_U}" "${PLIST}" >>"${LOG}" 2>&1 || \
			/usr/bin/sudo -u "${CONSOLE_USER}" "${LC}" load "${PLIST}" >>"${LOG}" 2>&1 || true
	fi
else
	log "==> No console user; skip first-run wizard (run ${FIRSTRUN} after login)"
fi

log "=== postinstall finished ok ==="
exit 0
