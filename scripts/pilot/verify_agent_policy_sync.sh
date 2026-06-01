#!/usr/bin/env bash
# Verify local agent applied a control-plane policy hash (post-sync).
set -euo pipefail

DATA_DIR="${1:-${EDR_AGENT_DATA_DIR:-}}"
if [[ -z "${DATA_DIR}" ]]; then
	case "$(uname -s)" in
	Linux) DATA_DIR="/var/lib/edr-agent" ;;
	Darwin) DATA_DIR="/Library/Application Support/EDR" ;;
	MINGW*|MSYS*|CYGWIN*|*)
		if [[ "${OS:-}" == "Windows_NT" ]]; then
			DATA_DIR="${PROGRAMDATA:-/c/ProgramData}/EDR Agent"
		else
			echo "usage: $0 [agent-data-dir]" >&2
			exit 1
		fi
		;;
	esac
fi

HASH_FILE="${DATA_DIR}/controlplane-policy.hash"
if [[ ! -f "${HASH_FILE}" ]]; then
	echo "ERROR: no control plane policy hash at ${HASH_FILE}" >&2
	echo "  Agent may not have synced policy yet (wait for policy loop or restart agent)." >&2
	exit 1
fi

HASH="$(tr -d '[:space:]' < "${HASH_FILE}")"
if [[ -z "${HASH}" || "${HASH}" == "local-default" ]]; then
	echo "ERROR: invalid policy hash in ${HASH_FILE}: ${HASH}" >&2
	exit 1
fi

echo "agent policy hash: ${HASH}"
echo "agent policy sync OK"
