#!/usr/bin/env bash
# Verify a specific agent_id appears in the control plane registry.
set -euo pipefail

HOST="${1:-}"
AGENT_ID="${2:-}"
TIMEOUT_SEC="${3:-${EDR_PILOT_ENROLL_TIMEOUT:-120}}"
HTTP_PORT="${EDR_CONTROLPLANE_HTTP_PORT:-8080}"
HTTPS="${EDR_CONTROLPLANE_HTTPS:-0}"
API_TOKEN="${EDR_CONTROLPLANE_API_TOKEN:-}"
AGENT_ID_FILE="${EDR_AGENT_ID_FILE:-}"

if [[ -z "${HOST}" ]]; then
	echo "usage: $0 <control-plane-host> [agent-id] [timeout-sec]" >&2
	exit 1
fi

if [[ -z "${AGENT_ID}" ]]; then
	for candidate in \
		"${AGENT_ID_FILE}" \
		"/var/lib/edr-agent/agent_id" \
		"/Library/Application Support/EDR/agent_id" \
		"/c/ProgramData/EDR Agent/agent_id"; do
		if [[ -n "${candidate}" && -f "${candidate}" ]]; then
			AGENT_ID="$(tr -d '[:space:]' < "${candidate}")"
			break
		fi
	done
fi
if [[ -z "${AGENT_ID}" ]]; then
	echo "ERROR: agent_id not provided and not found locally" >&2
	exit 1
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
URL="${SCHEME}://${HOST}:${HTTP_PORT}/v1/agents"

agent_enrolled() {
	curl -fsS "${CURL_OPTS[@]}" "${URL}" | python3 -c '
import json, sys
agent_id = sys.argv[1]
data = json.load(sys.stdin)
for agent in data.get("agents") or []:
    if agent.get("agent_id") == agent_id:
        print(json.dumps(agent))
        sys.exit(0)
sys.exit(1)
' "${AGENT_ID}"
}

deadline=$((SECONDS + TIMEOUT_SEC))
while (( SECONDS < deadline )); do
	if record="$(agent_enrolled 2>/dev/null || true)"; then
		echo "agent enrolled: ${AGENT_ID}"
		echo "${record}" | python3 -m json.tool 2>/dev/null || echo "${record}"
		exit 0
	fi
	echo "waiting for agent ${AGENT_ID} on control plane..."
	sleep 5
done

echo "ERROR: agent ${AGENT_ID} not found on control plane within ${TIMEOUT_SEC}s" >&2
exit 1
