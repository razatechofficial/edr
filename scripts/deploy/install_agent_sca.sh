#!/usr/bin/env bash
# Install offline SCA compliance policies onto a local agent.
set -euo pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 <sca-source-dir> <linux|macos|windows|all>" >&2
	echo "  source must contain linux/, windows/, and/or darwin/ subdirectories" >&2
	echo "  env: EDR_SCA_DEST to override install directory" >&2
	exit 1
fi

SRC="$1"
TARGET="$2"

sca_subdir() {
	case "$1" in
	linux) echo "linux" ;;
	macos) echo "darwin" ;;
	windows) echo "windows" ;;
	all) echo "all" ;;
	*) return 1 ;;
	esac
}

case "${TARGET}" in
linux)
	DEST="${EDR_SCA_DEST:-/etc/edr-agent/rules/compliance/sca}"
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: Run as root (sudo)." >&2
		exit 1
	fi
	;;
macos)
	DEST="${EDR_SCA_DEST:-/Library/Application Support/EDR/config/rules/compliance/sca}"
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: Run as root (sudo)." >&2
		exit 1
	fi
	;;
windows)
	DEST="${EDR_SCA_DEST:-${PROGRAMDATA:-/c/ProgramData}/EDR Agent/rules/compliance/sca}"
	;;
all)
	DEST="${EDR_SCA_DEST:-/etc/edr-agent/rules/compliance/sca}"
	if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
		echo "ERROR: Run as root (sudo)." >&2
		exit 1
	fi
	;;
*)
	echo "unknown target: ${TARGET}" >&2
	exit 1
	;;
esac

install_tree() {
	local sub="$1"
	local from="${SRC}/${sub}"
	local to="${DEST}/${sub}"
	if [[ ! -d "${from}" ]]; then
		echo "skip missing ${from}" >&2
		return 0
	fi
	mkdir -p "${to}"
	cp -R "${from}/." "${to}/"
	echo "  ${sub} -> ${to}"
}

mkdir -p "${DEST}"
mapped="$(sca_subdir "${TARGET}")" || {
	echo "unknown target: ${TARGET}" >&2
	exit 1
}

if [[ "${mapped}" == "all" ]]; then
	for sub in linux windows darwin; do
		install_tree "${sub}"
	done
else
	install_tree "${mapped}"
fi

echo "SCA policies installed under ${DEST}"
