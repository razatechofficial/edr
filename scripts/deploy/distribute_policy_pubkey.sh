#!/usr/bin/env bash
# Copy policy bundle verification public key to a remote agent host over SSH.
set -euo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <pubkey-source> <agent-host> [linux|macos|windows]" >&2
	echo "  env: EDR_SSH_USER (default: root for linux, current user otherwise)" >&2
	exit 1
fi

SRC="$1"
HOST="$2"
PLATFORM="${3:-linux}"

if [[ ! -f "${SRC}" ]]; then
	echo "missing pubkey: ${SRC}" >&2
	exit 1
fi

SSH_USER="${EDR_SSH_USER:-}"
case "${PLATFORM}" in
linux)
	SSH_USER="${SSH_USER:-root}"
	REMOTE_DEST="/etc/edr/certs"
	REMOTE_FILE="${REMOTE_DEST}/edr-policy.pub.pem"
	REMOTE_PREP="install -d -m 0750 ${REMOTE_DEST}"
	REMOTE_PERMS="chmod 0644 ${REMOTE_FILE}"
	;;
macos)
	SSH_USER="${SSH_USER:-${USER:-root}}"
	REMOTE_DEST="/etc/edr/certs"
	REMOTE_FILE="${REMOTE_DEST}/edr-policy.pub.pem"
	REMOTE_PREP="install -d -m 0750 ${REMOTE_DEST}"
	REMOTE_PERMS="chmod 0644 '${REMOTE_FILE}'"
	;;
windows)
	SSH_USER="${SSH_USER:-Administrator}"
	REMOTE_DEST='C:/ProgramData/EDR Agent/certs'
	REMOTE_FILE="${REMOTE_DEST}/edr-policy.pub.pem"
	REMOTE_PREP='powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path ''C:\ProgramData\EDR Agent\certs'' | Out-Null"'
	REMOTE_PERMS=""
	;;
*)
	echo "unknown platform: ${PLATFORM} (use linux, macos, or windows)" >&2
	exit 1
	;;
esac

SSH_TARGET="${SSH_USER}@${HOST}"

echo "==> Installing policy verify pubkey on ${SSH_TARGET}:${REMOTE_FILE} (${PLATFORM})"
ssh "${SSH_TARGET}" "${REMOTE_PREP}"
scp "${SRC}" "${SSH_TARGET}:${REMOTE_FILE}"
if [[ -n "${REMOTE_PERMS}" ]]; then
	ssh "${SSH_TARGET}" "${REMOTE_PERMS}"
fi
echo "Policy pubkey installed on ${SSH_TARGET}:${REMOTE_FILE}"
