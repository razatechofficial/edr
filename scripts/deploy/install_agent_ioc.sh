#!/usr/bin/env bash
# Install offline IOC databases onto a local agent (linux, macos, or windows).
set -euo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <ioc-source-dir> <linux|macos|windows>" >&2
	echo "  env: EDR_IOC_DEST to override install directory" >&2
	exit 1
fi

SRC="$1"
TARGET="$2"

for f in hashes.json ips.csv domains.csv; do
	if [[ ! -f "${SRC}/${f}" ]]; then
		echo "missing ${SRC}/${f}" >&2
		exit 1
	fi
done

case "${TARGET}" in
linux)
	DEST="${EDR_IOC_DEST:-/etc/edr-agent/rules/ioc}"
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: Run as root (sudo)." >&2
		exit 1
	fi
	;;
macos)
	DEST="${EDR_IOC_DEST:-/Library/Application Support/EDR/config/rules/ioc}"
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: Run as root (sudo)." >&2
		exit 1
	fi
	;;
windows)
	DEST="${EDR_IOC_DEST:-${PROGRAMDATA:-/c/ProgramData}/EDR Agent/rules/ioc}"
	;;
*)
	echo "unknown target: ${TARGET} (use linux, macos, or windows)" >&2
	exit 1
	;;
esac

mkdir -p "${DEST}"
install -m 0644 "${SRC}/hashes.json" "${SRC}/ips.csv" "${SRC}/domains.csv" "${DEST}/" 2>/dev/null || {
	cp "${SRC}/hashes.json" "${SRC}/ips.csv" "${SRC}/domains.csv" "${DEST}/"
}
if [[ -f "${SRC}/kev.json" ]]; then
	install -m 0644 "${SRC}/kev.json" "${DEST}/" 2>/dev/null || cp "${SRC}/kev.json" "${DEST}/"
fi

echo "IOC databases installed at ${DEST}"
