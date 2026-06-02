#!/usr/bin/env bash
# Copy policy verify public key from a local bundle directory to the agent.
set -euo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <pubkey-source-dir> <linux|macos|windows>" >&2
	exit 1
fi

SRC="$1"
TARGET="$2"
PUB="${SRC}/edr-policy.pub.pem"

if [[ ! -f "${PUB}" ]]; then
	echo "missing ${PUB}" >&2
	exit 1
fi

case "${TARGET}" in
linux)
	DEST="${EDR_CERTS_DEST:-/etc/edr/certs}"
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: Run as root (sudo)." >&2
		exit 1
	fi
	;;
macos)
	DEST="${EDR_CERTS_DEST:-/etc/edr/certs}"
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: Run as root (sudo)." >&2
		exit 1
	fi
	;;
windows)
	DEST="${EDR_CERTS_DEST:-${PROGRAMDATA:-/c/ProgramData}/EDR Agent/certs}"
	;;
*)
	echo "unknown target: ${TARGET}" >&2
	exit 1
	;;
esac

mkdir -p "${DEST}"
install -m 0644 "${PUB}" "${DEST}/edr-policy.pub.pem" 2>/dev/null || cp "${PUB}" "${DEST}/edr-policy.pub.pem"
echo "Policy verify pubkey installed at ${DEST}/edr-policy.pub.pem"
