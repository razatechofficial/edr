#!/usr/bin/env bash
# Compare control plane and local agent policy hashes.
set -euo pipefail

HOST="${1:-${EDR_CONTROL_PLANE_HOST:-}}"
DATA_DIR="${2:-${EDR_AGENT_DATA_DIR:-}}"
HTTP_PORT="${EDR_CONTROLPLANE_HTTP_PORT:-8080}"
HTTPS="${EDR_CONTROLPLANE_HTTPS:-0}"
API_TOKEN="${EDR_CONTROLPLANE_API_TOKEN:-}"

if [[ -z "${HOST}" ]]; then
	echo "usage: $0 <control-plane-host> [agent-data-dir]" >&2
	exit 1
fi

if [[ -z "${DATA_DIR}" ]]; then
	case "$(uname -s)" in
	Linux) DATA_DIR="/var/lib/edr-agent" ;;
	Darwin) DATA_DIR="/Library/Application Support/EDR" ;;
	MINGW*|MSYS*|CYGWIN*|*)
		if [[ "${OS:-}" == "Windows_NT" ]]; then
			DATA_DIR="${PROGRAMDATA:-/c/ProgramData}/EDR Agent"
		else
			echo "usage: $0 <control-plane-host> [agent-data-dir]" >&2
			exit 1
		fi
		;;
	esac
fi

SCHEME="http"
CURL_OPTS=()
if [[ "${HTTPS}" == "1" || "${HTTPS}" == "true" ]]; then
	SCHEME="https"
	CURL_OPTS+=(--cacert "${EDR_CONTROLPLANE_CA:-/etc/edr-controlplane/tls/ca.crt}")
fi
if [[ -n "${API_TOKEN}" ]]; then
	CURL_OPTS+=(-H "Authorization: Bearer ${API_TOKEN}")
fi

POLICY_URL="${SCHEME}://${HOST}:${HTTP_PORT}/v1/policy"
CP_TMP="$(mktemp)"
trap 'rm -f "${CP_TMP}"' EXIT

curl -fsS "${CURL_OPTS[@]}" "${POLICY_URL}" > "${CP_TMP}"

HASH_FILE="${DATA_DIR}/controlplane-policy.hash"
if [[ ! -f "${HASH_FILE}" ]]; then
	echo "ERROR: missing agent policy hash: ${HASH_FILE}" >&2
	exit 1
fi

export CP_TMP HASH_FILE
python3 - <<'PY'
import json, os, sys

with open(os.environ["CP_TMP"], encoding="utf-8") as f:
    cp = json.load(f)
cp_hash = (cp.get("policy_hash") or "").strip()
agent_hash = open(os.environ["HASH_FILE"], encoding="utf-8").read().strip()

if cp_hash in ("", "local-default"):
    raise SystemExit("ERROR: control plane has no staged policy bundles")
if agent_hash in ("", "local-default"):
    raise SystemExit(f"ERROR: invalid agent policy hash: {agent_hash!r}")
if cp_hash != agent_hash:
    raise SystemExit(
        f"ERROR: policy hash mismatch\n"
        f"  control plane: {cp_hash}\n"
        f"  agent:         {agent_hash}"
    )

print(f"policy hash matched: {cp_hash}")
print(f"policy bundles on CP: {len(cp.get('bundles') or [])}")
PY

echo "policy sync verification OK"
