#!/usr/bin/env bash
# Copy control-plane TLS client material to an agent host (Linux package layout).
set -euo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <tls-source-dir> <agent-host>" >&2
	echo "  Copies ca.crt + agent-client.{crt,key} to root@${2}:/etc/edr-agent/tls/" >&2
	exit 1
fi

SRC="$1"
HOST="$2"
DEST="/etc/edr-agent/tls"

for f in ca.crt agent-client.crt agent-client.key; do
	if [[ ! -f "${SRC}/${f}" ]]; then
		echo "missing ${SRC}/${f}" >&2
		exit 1
	fi
done

ssh "root@${HOST}" "install -d -m 0750 ${DEST}"
scp "${SRC}/ca.crt" "${SRC}/agent-client.crt" "${SRC}/agent-client.key" "root@${HOST}:${DEST}/"
ssh "root@${HOST}" "chmod 0644 ${DEST}/ca.crt ${DEST}/agent-client.crt && chmod 0600 ${DEST}/agent-client.key"
echo "Agent TLS material installed on ${HOST}:${DEST}"
