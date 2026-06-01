#!/usr/bin/env bash
# Verify a deployed control plane is reachable and optionally show enrolled agents.
set -euo pipefail

HOST="${1:-localhost}"
HTTP_PORT="${EDR_CONTROLPLANE_HTTP_PORT:-8080}"
GRPC_PORT="${EDR_CONTROLPLANE_GRPC_PORT:-50051}"
HTTP_URL="http://${HOST}:${HTTP_PORT}/healthz"
AGENTS_URL="http://${HOST}:${HTTP_PORT}/v1/agents"

echo "==> HTTP health: ${HTTP_URL}"
if ! curl -fsS "${HTTP_URL}"; then
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
curl -fsS "${AGENTS_URL}" | python3 -m json.tool 2>/dev/null || curl -fsS "${AGENTS_URL}"
echo
echo "control plane pilot check OK"
