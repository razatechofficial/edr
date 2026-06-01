#!/usr/bin/env bash
# Smoke-test local detection and optional control-plane alert forwarding.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CP_HOST="${1:-}"
ALERT_FILE="${EDR_ALERT_FILE:-/var/lib/edr-agent/alerts.jsonl}"
TIMEOUT="${EDR_PILOT_ALERT_TIMEOUT:-30}"
HTTPS="${EDR_CONTROLPLANE_HTTPS:-0}"
API_TOKEN="${EDR_CONTROLPLANE_API_TOKEN:-}"
HTTP_PORT="${EDR_CONTROLPLANE_HTTP_PORT:-8080}"

if [[ "$(uname -s)" == "Darwin" ]]; then
	ALERT_FILE="${EDR_ALERT_FILE:-/Library/Application Support/EDR/alerts/alerts.jsonl}"
fi

probe_dir="$(mktemp -d /tmp/edr-pilot-probe.XXXXXX)"
probe_file="${probe_dir}/log4j_yara_probe.txt"
baseline_cp=0

cp_alert_count() {
	local scheme="http"
	local curl_opts=()
	if [[ "${HTTPS}" == "1" || "${HTTPS}" == "true" ]]; then
		scheme="https"
		curl_opts+=(--cacert "${EDR_CONTROLPLANE_CA:-/etc/edr-controlplane/tls/ca.crt}")
	fi
	if [[ -n "${API_TOKEN}" ]]; then
		curl_opts+=(-H "Authorization: Bearer ${API_TOKEN}")
	fi
	curl -fsS "${curl_opts[@]}" "${scheme}://${CP_HOST}:${HTTP_PORT}/v1/alerts?limit=500" \
		| python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("alerts") or []))'
}

if [[ -n "${CP_HOST}" ]]; then
	baseline_cp="$(cp_alert_count || echo 0)"
fi

echo "==> trigger Log4Shell YARA probe"
printf '%s\n' '${jndi:ldap://127.0.0.1/edr-pilot-probe}' > "${probe_file}"
chmod 644 "${probe_file}"

echo "==> wait for local alert (${ALERT_FILE})"
deadline=$((SECONDS + TIMEOUT))
found=0
while (( SECONDS < deadline )); do
	if [[ -f "${ALERT_FILE}" ]] && tail -50 "${ALERT_FILE}" | grep -Eiq 'Log4Shell|log4j|jndi'; then
		found=1
		break
	fi
	sleep 2
done
if [[ "${found}" -ne 1 ]]; then
	echo "ERROR: no local detection alert observed within ${TIMEOUT}s" >&2
	rm -rf "${probe_dir}"
	exit 1
fi
echo "local detection alert observed"

if [[ -n "${CP_HOST}" ]]; then
	echo "==> wait for control plane alert forwarding"
	bash "${ROOT}/scripts/pilot/wait_for_cp_alerts.sh" "${CP_HOST}" 1 "${baseline_cp}" "${TIMEOUT}"
fi

rm -rf "${probe_dir}"
echo "detection pipeline pilot check OK"
