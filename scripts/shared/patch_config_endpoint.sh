#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 <config.yml> <control-plane-host>" >&2
	exit 1
fi

CONFIG="$1"
HOST="$2"

if [[ ! -f "${CONFIG}" ]]; then
	echo "config not found: ${CONFIG}" >&2
	exit 1
fi
if [[ -z "${HOST}" || "${HOST}" == *" "* ]]; then
	echo "invalid control-plane host: ${HOST}" >&2
	exit 1
fi

if grep -q 'YOUR_CONTROL_PLANE_HOST' "${CONFIG}"; then
	sed -i.bak "s/YOUR_CONTROL_PLANE_HOST/${HOST}/g" "${CONFIG}"
	rm -f "${CONFIG}.bak"
else
	echo "warning: placeholder YOUR_CONTROL_PLANE_HOST not found in ${CONFIG}" >&2
fi
