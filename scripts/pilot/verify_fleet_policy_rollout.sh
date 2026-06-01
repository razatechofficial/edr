#!/usr/bin/env bash
# Verify enrolled agents report the same policy hash as the control plane.
set -euo pipefail

HOST="${1:-localhost}"
EXPECTED="${2:-}"
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

POLICY_URL="${SCHEME}://${HOST}:${HTTP_PORT}/v1/policy"
AGENTS_URL="${SCHEME}://${HOST}:${HTTP_PORT}/v1/agents"
POLICY_TMP="$(mktemp)"
AGENTS_TMP="$(mktemp)"
trap 'rm -f "${POLICY_TMP}" "${AGENTS_TMP}"' EXIT

curl -fsS "${CURL_OPTS[@]}" "${POLICY_URL}" > "${POLICY_TMP}"
curl -fsS "${CURL_OPTS[@]}" "${AGENTS_URL}" > "${AGENTS_TMP}"

export EXPECTED
python3 - <<'PY' "${POLICY_TMP}" "${AGENTS_TMP}"
import json, os, sys

with open(sys.argv[1], encoding="utf-8") as f:
    policy = json.load(f)
with open(sys.argv[2], encoding="utf-8") as f:
    agents = json.load(f).get("agents") or []

cp_hash = (policy.get("policy_hash") or "").strip()
bundles = policy.get("bundles") or []
expected = os.environ.get("EXPECTED", "").strip()

if cp_hash in ("", "local-default"):
    raise SystemExit("ERROR: control plane has no staged policy bundles")

print(f"control plane policy: {cp_hash} ({len(bundles)} bundle(s))")
if not agents:
    print("WARNING: no enrolled agents")
    sys.exit(0)

matched = 0
missing = []
stale = []
for agent in agents:
    agent_id = agent.get("agent_id", "?")
    reported = (agent.get("policy_hash") or "").strip()
    if not reported:
        missing.append(agent_id)
    elif reported != cp_hash:
        stale.append(f"{agent_id} ({reported[:12]}...)")
    else:
        matched += 1

print(f"agents reporting current policy: {matched}/{len(agents)}")
if missing:
    print(f"  missing policy_hash (awaiting sync): {', '.join(missing)}")
if stale:
    raise SystemExit(f"ERROR: policy hash mismatch on: {', '.join(stale)}")

if expected:
    want = int(expected)
    if len(agents) < want:
        raise SystemExit(f"ERROR: enrolled agents {len(agents)} < expected {want}")
    if matched < want:
        raise SystemExit(f"ERROR: only {matched}/{want} agents report current policy")

print("fleet policy rollout OK")
PY
