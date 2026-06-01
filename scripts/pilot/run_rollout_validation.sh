#!/usr/bin/env bash
# Post-rollout validation gate: fleet counts and recent heartbeats.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST="${1:-}"
EXPECTED="${2:-1}"
STALE_SEC="${EDR_ROLLOUT_STALE_SEC:-180}"

if [[ -z "${HOST}" ]]; then
	echo "usage: $0 <control-plane-host> [expected-agents]" >&2
	exit 1
fi

bash "${ROOT}/scripts/pilot/rollout_status.sh" "${HOST}" "${EXPECTED}"

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

AGENTS_TMP="$(mktemp)"
trap 'rm -f "${AGENTS_TMP}"' EXIT
curl -fsS "${CURL_OPTS[@]}" "${SCHEME}://${HOST}:${HTTP_PORT}/v1/agents" > "${AGENTS_TMP}"

export STALE_SEC EXPECTED
python3 - <<'PY' "${AGENTS_TMP}"
import json, os, sys
from datetime import datetime, timezone, timedelta

with open(sys.argv[1], encoding="utf-8") as f:
    agents = json.load(f).get("agents") or []
expected = int(os.environ.get("EXPECTED", "0") or "0")
stale_sec = int(os.environ.get("STALE_SEC", "180"))
cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale_sec)

if expected and len(agents) < expected:
    print(f"ERROR: enrolled agents {len(agents)} < expected {expected}", file=sys.stderr)
    sys.exit(1)

stale = []
for agent in agents:
    raw = agent.get("last_heartbeat") or ""
    if not raw:
        stale.append(agent.get("agent_id", "?"))
        continue
    ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    if ts < cutoff:
        stale.append(agent.get("agent_id", "?"))

if stale:
    print(f"ERROR: stale heartbeats (> {stale_sec}s): {', '.join(stale)}", file=sys.stderr)
    sys.exit(1)

print(f"rollout validation OK ({len(agents)} agent(s), heartbeats within {stale_sec}s)")
PY
