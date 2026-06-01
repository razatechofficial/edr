#!/usr/bin/env bash
# Summarize control plane and fleet rollout status.
set -euo pipefail

HOST="${1:-localhost}"
EXPECTED="${2:-}"
HTTP_PORT="${EDR_CONTROLPLANE_HTTP_PORT:-8080}"
GRPC_PORT="${EDR_CONTROLPLANE_GRPC_PORT:-50051}"
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

HEALTH_URL="${SCHEME}://${HOST}:${HTTP_PORT}/healthz"
AGENTS_URL="${SCHEME}://${HOST}:${HTTP_PORT}/v1/agents"
ALERTS_URL="${SCHEME}://${HOST}:${HTTP_PORT}/v1/alerts?limit=500"

echo "==> control plane ${HOST}"
echo "    HTTP:  ${HEALTH_URL}"
echo "    gRPC:  ${HOST}:${GRPC_PORT}"

if ! curl -fsS "${CURL_OPTS[@]}" "${HEALTH_URL}" >/dev/null; then
	echo "ERROR: control plane health check failed" >&2
	exit 1
fi
echo "    health: OK"

if command -v nc >/dev/null 2>&1; then
	if nc -z -w 3 "${HOST}" "${GRPC_PORT}" 2>/dev/null; then
		echo "    gRPC port: reachable"
	else
		echo "    gRPC port: unreachable" >&2
	fi
fi

AGENTS_TMP="$(mktemp)"
ALERTS_TMP="$(mktemp)"
trap 'rm -f "${AGENTS_TMP}" "${ALERTS_TMP}"' EXIT
curl -fsS "${CURL_OPTS[@]}" "${AGENTS_URL}" > "${AGENTS_TMP}"
curl -fsS "${CURL_OPTS[@]}" "${ALERTS_URL}" > "${ALERTS_TMP}"

export EXPECTED
python3 - <<'PY' "${AGENTS_TMP}" "${ALERTS_TMP}"
import json, os, sys

with open(sys.argv[1], encoding="utf-8") as f:
    agents = json.load(f).get("agents") or []
with open(sys.argv[2], encoding="utf-8") as f:
    alerts = json.load(f).get("alerts") or []
expected = os.environ.get("EXPECTED", "")

print()
print("Fleet summary:")
print(f"  enrolled agents: {len(agents)}")
print(f"  ingested alerts: {len(alerts)}")
if expected:
    want = int(expected)
    if len(agents) >= want:
        print(f"  expected agents ({want}): OK")
    else:
        print(f"  expected agents ({want}): SHORT ({len(agents)}/{want})")

if agents:
    print("  recent agents:")
    for agent in agents[:10]:
        print(
            f"    - {agent.get('agent_id', '?')} "
            f"{agent.get('hostname', '?')} ({agent.get('os', '?')}) "
            f"heartbeat={agent.get('last_heartbeat', '')}"
        )
    if len(agents) > 10:
        print(f"    ... and {len(agents) - 10} more")
PY

echo
echo "rollout status OK"
