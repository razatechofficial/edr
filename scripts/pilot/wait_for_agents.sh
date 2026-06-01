#!/usr/bin/env bash
# Wait until the control plane reports at least N enrolled agents.
set -euo pipefail

HOST="${1:-localhost}"
WANT="${2:-1}"
TIMEOUT_SEC="${3:-300}"
HTTP_PORT="${EDR_CONTROLPLANE_HTTP_PORT:-8080}"
HTTPS="${EDR_CONTROLPLANE_HTTPS:-0}"
API_TOKEN="${EDR_CONTROLPLANE_API_TOKEN:-}"
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
deadline=$((SECONDS + TIMEOUT_SEC))

agent_count() {
	curl -fsS "${CURL_OPTS[@]}" "${URL}" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(len(data.get("agents") or []))'
}

while (( SECONDS < deadline )); do
	count="$(agent_count || echo 0)"
	if [[ "${count}" -ge "${WANT}" ]]; then
		echo "enrolled agents: ${count} (target ${WANT})"
		exit 0
	fi
	echo "waiting for agents (${count}/${WANT})..."
	sleep 5
done

echo "ERROR: timed out waiting for ${WANT} enrolled agent(s)" >&2
exit 1
