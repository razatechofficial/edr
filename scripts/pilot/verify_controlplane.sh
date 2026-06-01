#!/usr/bin/env bash
# Verify a deployed control plane is reachable and optionally show enrolled agents.
set -euo pipefail

HOST="${1:-localhost}"
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
ALERTS_URL="${SCHEME}://${HOST}:${HTTP_PORT}/v1/alerts?limit=5"

echo "==> HTTP health: ${HEALTH_URL}"
if ! curl -fsS "${CURL_OPTS[@]}" "${HEALTH_URL}"; then
	echo
	echo "ERROR: control plane HTTP health check failed" >&2
	exit 1
fi
echo

echo "==> gRPC port ${HOST}:${GRPC_PORT}"
if command -v nc >/dev/null 2>&1; then
	if nc -z -w 3 "${HOST}" "${GRPC_PORT}" 2>/dev/null; then
		echo "gRPC port open"
	else
		echo "ERROR: gRPC port not reachable" >&2
		exit 1
	fi
else
	echo "skip TCP probe (nc not installed)"
fi

echo
echo "==> enrolled agents: ${AGENTS_URL}"
curl -fsS "${CURL_OPTS[@]}" "${AGENTS_URL}" | python3 -m json.tool 2>/dev/null || curl -fsS "${CURL_OPTS[@]}" "${AGENTS_URL}"
echo
echo "==> recent alerts: ${ALERTS_URL}"
curl -fsS "${CURL_OPTS[@]}" "${ALERTS_URL}" | python3 -m json.tool 2>/dev/null || curl -fsS "${CURL_OPTS[@]}" "${ALERTS_URL}"
echo
echo "control plane pilot check OK"
