#!/usr/bin/env bash
# Verify control plane policy bundles are published over HTTP.
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

POLICY_URL="${SCHEME}://${HOST}:${HTTP_PORT}/v1/policy"
TMP="$(mktemp)"
trap 'rm -f "${TMP}"' EXIT

echo "==> policy: ${POLICY_URL}"
curl -fsS "${CURL_OPTS[@]}" "${POLICY_URL}" > "${TMP}"
python3 -m json.tool "${TMP}"

python3 - <<'PY' "${TMP}"
import json, sys

with open(sys.argv[1], encoding="utf-8") as f:
    payload = json.load(f)

policy_hash = payload.get("policy_hash") or ""
bundles = payload.get("bundles") or []
if policy_hash in ("", "local-default"):
    raise SystemExit("ERROR: no staged policy bundles on control plane")

print(f"policy hash: {policy_hash}")
print(f"bundles: {len(bundles)}")
for bundle in bundles:
    print(f"  - {bundle.get('name')} ({bundle.get('version')}) {bundle.get('hash')}")
PY

echo "control plane policy OK"
