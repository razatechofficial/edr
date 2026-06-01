#!/usr/bin/env bash
# Wait until the control plane reports at least N alerts (or an increase from baseline).
set -euo pipefail

HOST="${1:-localhost}"
WANT="${2:-1}"
BASELINE="${3:-0}"
TIMEOUT_SEC="${4:-300}"
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

URL="${SCHEME}://${HOST}:${HTTP_PORT}/v1/alerts?limit=500"
deadline=$((SECONDS + TIMEOUT_SEC))

alert_count() {
	curl -fsS "${CURL_OPTS[@]}" "${URL}" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(len(data.get("alerts") or []))'
}

target=$((BASELINE + WANT))
while (( SECONDS < deadline )); do
	count="$(alert_count || echo 0)"
	if [[ "${count}" -ge "${target}" ]]; then
		echo "control plane alerts: ${count} (target >= ${target})"
		exit 0
	fi
	echo "waiting for alerts (${count}/${target})..."
	sleep 5
done

echo "ERROR: timed out waiting for ${WANT} new control plane alert(s)" >&2
exit 1
