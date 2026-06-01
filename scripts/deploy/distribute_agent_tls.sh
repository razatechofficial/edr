#!/usr/bin/env bash
# Copy control-plane TLS client material to a remote agent host over SSH.
set -euo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <tls-source-dir> <agent-host> [linux|macos|windows]" >&2
	echo "  env: EDR_SSH_USER (default: root for linux, current user otherwise)" >&2
	exit 1
fi

SRC="$1"
HOST="$2"
PLATFORM="${3:-linux}"

for f in ca.crt agent-client.crt agent-client.key; do
	if [[ ! -f "${SRC}/${f}" ]]; then
		echo "missing ${SRC}/${f}" >&2
		exit 1
	fi
done

SSH_USER="${EDR_SSH_USER:-}"
case "${PLATFORM}" in
linux)
	SSH_USER="${SSH_USER:-root}"
	REMOTE_DEST="/etc/edr-agent/tls"
	REMOTE_PREP="install -d -m 0750 ${REMOTE_DEST}"
	REMOTE_PERMS="chmod 0644 ${REMOTE_DEST}/ca.crt ${REMOTE_DEST}/agent-client.crt && chmod 0600 ${REMOTE_DEST}/agent-client.key"
	;;
macos)
	SSH_USER="${SSH_USER:-${USER:-root}}"
	REMOTE_DEST="/Library/Application Support/EDR/tls"
	REMOTE_PREP="install -d -m 0750 '${REMOTE_DEST}'"
	REMOTE_PERMS="chmod 0644 '${REMOTE_DEST}/ca.crt' '${REMOTE_DEST}/agent-client.crt' && chmod 0600 '${REMOTE_DEST}/agent-client.key'"
	;;
windows)
	SSH_USER="${SSH_USER:-Administrator}"
	REMOTE_DEST='C:/ProgramData/EDR Agent/tls'
	REMOTE_PREP='powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path ''C:\ProgramData\EDR Agent\tls'' | Out-Null"'
	REMOTE_PERMS='powershell -NoProfile -Command "$k=''C:\ProgramData\EDR Agent\tls\agent-client.key''; if (Test-Path -LiteralPath $k) { icacls $k /inheritance:r /grant:r ''Administrators:F'' ''SYSTEM:F'' | Out-Null }"'
	;;
*)
	echo "unknown platform: ${PLATFORM} (use linux, macos, or windows)" >&2
	exit 1
	;;
esac

SSH_TARGET="${SSH_USER}@${HOST}"

echo "==> Installing agent TLS on ${SSH_TARGET}:${REMOTE_DEST} (${PLATFORM})"
ssh "${SSH_TARGET}" "${REMOTE_PREP}"
scp "${SRC}/ca.crt" "${SRC}/agent-client.crt" "${SRC}/agent-client.key" "${SSH_TARGET}:${REMOTE_DEST}/"
ssh "${SSH_TARGET}" "${REMOTE_PERMS}"
echo "Agent TLS material installed on ${SSH_TARGET}:${REMOTE_DEST}"
