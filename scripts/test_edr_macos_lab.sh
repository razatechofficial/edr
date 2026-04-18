#!/usr/bin/env bash
# Safe macOS lab helper: confirm the agent is running, validate the shipped rule
# stack (Sigma parse + YARA + ML inventory), and nudge the pipeline with a
# benign file that matches an *existing* YARA rule (no lab-only signatures).
#
# What gets exercised:
#   • Sigma — all rules under rules/sigma must parse (go test smoke).
#   • YARA — writes a Log4j JNDI test string; matches shipped rule
#     Exploit_CVE_2021_44228_Log4Shell in rules/yara/exploits/cve_2021_44228_log4j.yar
#     (IOC pattern only — not an exploit).
#   • ML — bundled ONNX models are listed from models/manifest.json; runtime scoring
#     runs on executable/network/process events per internal/detection/engine.go
#     (plain text JNDI files usually score low; ML is still loaded with run-agent-ml).
#
# Writes under /tmp and $HOME (FIM watches those on macOS).
#
# Usage (from repo root, agent already running e.g. `make run-agent-ml`):
#   chmod +x scripts/test_edr_macos_lab.sh
#   ./scripts/test_edr_macos_lab.sh
#
# Optional:
#   EDR_ALERT_FILE=/path/to/alerts.jsonl EDR_AUDIT_FILE=/path/to/audit.jsonl ./scripts/test_edr_macos_lab.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_DATA="${HOME}/Library/Application Support/EDR"
ALERT_FILE="${EDR_ALERT_FILE:-${DEFAULT_DATA}/alerts/alerts.jsonl}"
AUDIT_FILE="${EDR_AUDIT_FILE:-${DEFAULT_DATA}/audit/audit.jsonl}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== EDR agent macOS lab check ===${NC}"
echo "Repo:       ${ROOT_DIR}"
echo "Alert log:  ${ALERT_FILE}"
echo "Audit log:  ${AUDIT_FILE}"
echo ""

echo -e "${CYAN}=== Sigma rules (parse smoke) ===${NC}"
cd "${ROOT_DIR}"
if go test ./internal/detection/rules/... -run TestSigmaRulesParse -count=1 -timeout 60s; then
  echo -e "  ${GREEN}OK — all Sigma YAML files parse (rules/sigma).${NC}"
else
  echo -e "  ${RED}Sigma parse test failed (fix rules/sigma or sigma-go).${NC}"
fi
echo ""

MANIFEST="${ROOT_DIR}/models/manifest.json"
echo -e "${CYAN}=== ML models (bundled manifest) ===${NC}"
if [[ -f "${MANIFEST}" ]]; then
  echo "  ${MANIFEST}"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.models[]? | "  - \(.name) (\(.file))"' "${MANIFEST}" 2>/dev/null || cat "${MANIFEST}" | sed 's/^/  /'
  else
    grep -E '"name"|"file"' "${MANIFEST}" | head -20 | sed 's/^/  /'
  fi
else
  echo -e "  ${YELLOW}No models/manifest.json at repo root — ML may use defaults.${NC}"
fi
echo ""

agent_ok=0
if pgrep -f "edr-agent|cmd/agent" >/dev/null 2>&1; then
  echo -e "${GREEN}Agent process: found (pgrep).${NC}"
  agent_ok=1
else
  echo -e "${YELLOW}Agent process: not found — start the agent first (e.g. make run-agent-ml).${NC}"
fi

if [[ -f "${ALERT_FILE}" ]]; then
  echo -e "${GREEN}Alert file exists.${NC}"
else
  echo -e "${YELLOW}Alert file missing yet (${ALERT_FILE}).${NC}"
fi
echo ""

lines_before=0
if [[ -f "${ALERT_FILE}" ]]; then
  lines_before=$(wc -l < "${ALERT_FILE}" | tr -d ' ')
fi

STAMP="$(date +%s)-$$"
CANARY_TMP="/tmp/edr_macos_canary_${STAMP}.txt"
# Matches shipped YARA: Exploit_CVE_2021_44228_Log4Shell (cve_2021_44228_log4j.yar)
LOG4J_TMP="/tmp/edr_log4j_yara_probe_${STAMP}.txt"
CANARY_HOME="${HOME}/.edr_lab_canary_${STAMP}.txt"
LOG4J_HOME="${HOME}/.edr_lab_log4j_${STAMP}.txt"

echo "Writing benign probe files..."
echo "EDR macOS lab canary ${STAMP} — not malicious" > "${CANARY_TMP}"
# Benign detection string (IOC), not an active exploit.
printf '%s\n' '${jndi:ldap://127.0.0.1/edr-lab-probe}' > "${LOG4J_TMP}"
echo "EDR macOS lab canary (home) ${STAMP}" > "${CANARY_HOME}"
printf '%s\n' '${jndi:ldap://127.0.0.1/edr-lab-probe}' > "${LOG4J_HOME}"

echo "  ${CANARY_TMP}"
echo "  ${LOG4J_TMP}  (YARA: Exploit_CVE_2021_44228_Log4Shell)"
echo "  ${CANARY_HOME}"
echo "  ${LOG4J_HOME}"
echo ""
echo "Waiting 25s for FIM (fsnotify) + agent tick..."
sleep 25

lines_after=0
if [[ -f "${ALERT_FILE}" ]]; then
  lines_after=$(wc -l < "${ALERT_FILE}" | tr -d ' ')
fi
new_lines=$((lines_after - lines_before))

echo ""
echo -e "${CYAN}=== Alert log delta ===${NC}"
echo "Lines before: ${lines_before}"
echo "Lines after:  ${lines_after}"
echo "New lines:    ${new_lines}"
echo ""

if [[ "${new_lines}" -gt 0 ]] && [[ -f "${ALERT_FILE}" ]]; then
  echo "Last ${new_lines} line(s):"
  tail -n "${new_lines}" "${ALERT_FILE}" | sed 's/^/  /' || true
  if tail -n "${new_lines}" "${ALERT_FILE}" | grep -qE 'Log4Shell|44228|yara-Exploit_CVE_2021_44228'; then
    echo -e "${GREEN}Observed alert text consistent with shipped Log4Shell YARA rule.${NC}"
  fi
elif [[ -f "${ALERT_FILE}" ]]; then
  echo -e "${YELLOW}No new alert lines in this window.${NC}"
  echo "If the agent uses repo rules, the Log4j probe should match YARA once the file is scanned."
  echo "If still silent: confirm cwd/repo rules path, FIM paths, and agent YARA enabled."
  echo "Deeper scenarios: ./scripts/test_detections.sh --alert-file \"${ALERT_FILE}\""
else
  echo "No alert file to read yet."
fi

echo ""
echo -e "${CYAN}=== Kill / response (audit) ===${NC}"
echo "Auto-kill needs config + min score + PID > 0. File-only YARA hits often have pid=0."
echo ""
if [[ -f "${AUDIT_FILE}" ]]; then
  echo "Recent kill_process audit entries (may include older runs):"
  if grep -F "kill_process" "${AUDIT_FILE}" 2>/dev/null | tail -5 | sed 's/^/  /'; then
    :
  else
    echo "  (none)"
  fi
else
  echo "Audit file not found: ${AUDIT_FILE}"
fi

echo ""
echo -e "${CYAN}=== Cleanup ===${NC}"
rm -f "${CANARY_TMP}" "${LOG4J_TMP}" "${CANARY_HOME}" "${LOG4J_HOME}"
echo "Removed lab files under /tmp and \$HOME"

echo ""
if [[ "${agent_ok}" -eq 1 ]]; then
  echo -e "${GREEN}Done.${NC} See also: scripts/test_detections.sh"
  exit 0
fi
echo -e "${YELLOW}Start the agent and re-run this script.${NC}"
exit 1
