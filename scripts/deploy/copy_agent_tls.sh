#!/usr/bin/env bash
# Copy agent TLS client material from a control-plane host to a local agent directory.
set -euo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <tls-source-dir> <linux|macos|windows>" >&2
	exit 1
fi

SRC="$1"
TARGET="$2"

for f in ca.crt agent-client.crt agent-client.key; do
	if [[ ! -f "${SRC}/${f}" ]]; then
		echo "missing ${SRC}/${f}" >&2
		exit 1
	fi
done

case "${TARGET}" in
linux)
	DEST="/etc/edr-agent/tls"
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: Run as root (sudo)." >&2
		exit 1
	fi
	install -d -m 0750 "${DEST}"
	install -m 0644 "${SRC}/ca.crt" "${SRC}/agent-client.crt" "${DEST}/"
	install -m 0600 "${SRC}/agent-client.key" "${DEST}/"
	;;
macos)
	DEST="/Library/Application Support/EDR/tls"
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: Run as root (sudo)." >&2
		exit 1
	fi
	install -d -m 0750 "${DEST}"
	install -m 0644 "${SRC}/ca.crt" "${SRC}/agent-client.crt" "${DEST}/"
	install -m 0600 "${SRC}/agent-client.key" "${DEST}/"
	;;
windows)
	DEST="${PROGRAMDATA:-/c/ProgramData}/EDR Agent/tls"
	mkdir -p "${DEST}"
	cp "${SRC}/ca.crt" "${SRC}/agent-client.crt" "${DEST}/"
	cp "${SRC}/agent-client.key" "${DEST}/"
	chmod 600 "${DEST}/agent-client.key" 2>/dev/null || true
	;;
*)
	echo "unknown target: ${TARGET} (use linux, macos, or windows)" >&2
	exit 1
	;;
esac

echo "Agent TLS material installed at ${DEST}"
