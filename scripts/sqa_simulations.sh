#!/usr/bin/env bash
set -euo pipefail

# Safe, non-destructive simulations for SQA on an isolated lab host.
# Run after the agent is installed and running (or with --test-mode).

AGENT_BIN="${EDR_AGENT_BIN:-/usr/local/bin/edr-agent}"
CONFIG="${EDR_CONFIG:-/etc/edr-agent/agent.yaml}"
DATA_DIR="${EDR_DATA_DIR:-/var/lib/edr-agent}"
ALERT_FILE="${EDR_ALERT_FILE:-${DATA_DIR}/alerts.jsonl}"
TEST_MODE=0

usage() {
	cat <<'EOF'
Usage: sudo ./scripts/sqa_simulations.sh [--test-mode]

Runs built-in validation and a small set of safe local simulations.
Use only on an isolated lab VM. Do not run destructive ransomware payloads.
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		--test-mode)
			TEST_MODE=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown option: $1" >&2
			usage
			exit 1
			;;
	esac
done

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root: sudo $0" >&2
	exit 1
fi

if [ ! -x "${AGENT_BIN}" ]; then
	echo "agent binary not found: ${AGENT_BIN}" >&2
	exit 1
fi
if [ ! -f "${CONFIG}" ]; then
	echo "config not found: ${CONFIG}" >&2
	exit 1
fi

mkdir -p "${DATA_DIR}"

echo "=== EDR SQA simulations ==="
echo "agent:  ${AGENT_BIN}"
echo "config: ${CONFIG}"
echo "data:   ${DATA_DIR}"
echo

if [ "${TEST_MODE}" -eq 1 ]; then
	echo "==> Built-in validation suite"
	"${AGENT_BIN}" --config "${CONFIG}" --data-dir "${DATA_DIR}" --test-mode
	exit $?
fi

echo "==> Safe local simulations"
echo "    process/base64 pipe"
sh -c 'echo edr-sqa-test | base64 | sh 2>/dev/null || true'
echo "    sensitive file read"
cat /etc/passwd >/dev/null 2>&1 || true
cat /etc/shadow >/dev/null 2>&1 || true
echo "    temp executable write"
TMP_EXE="/tmp/edr_sqa_exec_$$"
printf '#!/bin/sh\necho edr-sqa\n' > "${TMP_EXE}"
chmod 755 "${TMP_EXE}"
rm -f "${TMP_EXE}"
echo "    eicar write"
EICAR="/tmp/edr_sqa_eicar_$$.txt"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "${EICAR}"
rm -f "${EICAR}"
echo "    local network dial"
(timeout 2 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/4444' 2>/dev/null || true)

echo
echo "==> Wait a few seconds, then inspect alerts and health"
echo "    journalctl -u edr-agent -n 100 --no-pager"
echo "    cat ${ALERT_FILE}"
echo "    cat ${DATA_DIR}/monitoring_health.json"
sleep 5
if [ -f "${ALERT_FILE}" ]; then
	echo
	echo "==> Recent alert lines"
	tail -n 20 "${ALERT_FILE}" || true
fi
