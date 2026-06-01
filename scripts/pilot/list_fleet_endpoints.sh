#!/usr/bin/env bash
# Summarize enrolled fleet endpoints from the control plane HTTP API.
set -euo pipefail

HOST="${1:-localhost}"
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

AGENTS_URL="${SCHEME}://${HOST}:${HTTP_PORT}/v1/agents"
AGENTS_TMP="$(mktemp)"
trap 'rm -f "${AGENTS_TMP}"' EXIT

curl -fsS "${CURL_OPTS[@]}" "${AGENTS_URL}" > "${AGENTS_TMP}"

python3 - <<'PY' "${AGENTS_TMP}"
import json, sys
from collections import Counter

with open(sys.argv[1], encoding="utf-8") as f:
    agents = json.load(f).get("agents") or []

print(f"enrolled agents: {len(agents)}")
if not agents:
    sys.exit(0)

by_os = Counter((a.get("os") or "?").lower() for a in agents)
print("by OS:", ", ".join(f"{k}={v}" for k, v in sorted(by_os.items())))

print()
print(f"{'AGENT_ID':<36} {'HOSTNAME':<24} {'OS':<10} {'VERSION':<12} LAST_HEARTBEAT")
for agent in agents:
    print(
        f"{agent.get('agent_id', '?'):<36} "
        f"{agent.get('hostname', '?'):<24} "
        f"{agent.get('os', '?'):<10} "
        f"{agent.get('version', '?'):<12} "
        f"{agent.get('last_heartbeat', '')}"
    )
PY
