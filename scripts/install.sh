#!/usr/bin/env bash
set -euo pipefail

# Install EDR agent on the current system.
#
# This script detects the OS and architecture, copies binaries to the
# appropriate system paths, creates the service definition, generates an
# initial configuration with a unique agent ID, and starts the agent.
#
# Usage:
#   sudo ./scripts/install.sh
#   sudo ./scripts/install.sh --data-dir /opt/edr --config /path/to/agent.yaml
#
# Environment:
#   EDR_DATA_DIR    Override data directory
#   EDR_CONFIG      Path to existing config file to install

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------- argument parsing ----------

DATA_DIR="${EDR_DATA_DIR:-}"
CONFIG_FILE="${EDR_CONFIG:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: sudo $0 [--data-dir DIR] [--config FILE]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ---------- privilege check ----------

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (use sudo)"
    exit 1
fi

# ---------- OS detection ----------

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)
        echo "Error: unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

echo "==> Detected OS=${OS} ARCH=${ARCH}"

# ---------- platform paths ----------

case "${OS}" in
    linux)
        BIN_DIR="/usr/local/bin"
        CONF_DIR="/etc/edr"
        DATA_DIR="${DATA_DIR:-/var/lib/edr}"
        LOG_DIR="/var/log/edr"
        RULES_DIR="/etc/edr/rules"
        ;;
    darwin)
        BIN_DIR="/usr/local/bin"
        CONF_DIR="/Library/Application Support/EDR/config"
        DATA_DIR="${DATA_DIR:-/Library/Application Support/EDR}"
        LOG_DIR="/Library/Logs/EDR"
        RULES_DIR="/Library/Application Support/EDR/rules"
        ;;
    *)
        echo "Error: unsupported OS: ${OS}"
        echo "For Windows, use the edr-installer.exe binary directly."
        exit 1
        ;;
esac

# ---------- locate binaries ----------

AGENT_BIN=""
EDRCTL_BIN=""

for candidate in \
    "${ROOT_DIR}/bin/edr-agent-${OS}-${ARCH}" \
    "${ROOT_DIR}/bin/edr-agent" \
    "${ROOT_DIR}/edr-agent"; do
    if [ -f "${candidate}" ]; then
        AGENT_BIN="${candidate}"
        break
    fi
done

if [ -z "${AGENT_BIN}" ]; then
    echo "Error: agent binary not found. Run 'make build' first."
    exit 1
fi

for candidate in \
    "${ROOT_DIR}/bin/edrctl-${OS}-${ARCH}" \
    "${ROOT_DIR}/bin/edrctl" \
    "${ROOT_DIR}/edrctl"; do
    if [ -f "${candidate}" ]; then
        EDRCTL_BIN="${candidate}"
        break
    fi
done

echo "==> Agent binary: ${AGENT_BIN}"
[ -n "${EDRCTL_BIN}" ] && echo "==> CLI binary:   ${EDRCTL_BIN}"

# ---------- create directories ----------

echo "==> Creating directories"
for dir in "${BIN_DIR}" "${CONF_DIR}" "${DATA_DIR}" "${LOG_DIR}" "${RULES_DIR}" \
           "${DATA_DIR}/quarantine" "${DATA_DIR}/forensics" "${DATA_DIR}/ioc" \
           "${DATA_DIR}/models" "${DATA_DIR}/vectordb"; do
    mkdir -p "${dir}"
    echo "    ${dir}"
done

# ---------- install binaries ----------

echo "==> Installing binaries"
install -m 0755 "${AGENT_BIN}" "${BIN_DIR}/edr-agent"
echo "    ${BIN_DIR}/edr-agent"

if [ -n "${EDRCTL_BIN}" ]; then
    install -m 0755 "${EDRCTL_BIN}" "${BIN_DIR}/edrctl"
    echo "    ${BIN_DIR}/edrctl"
fi

# ---------- install configuration ----------

DEST_CONFIG="${CONF_DIR}/agent.yaml"

if [ -n "${CONFIG_FILE}" ] && [ -f "${CONFIG_FILE}" ]; then
    echo "==> Installing provided config"
    install -m 0640 "${CONFIG_FILE}" "${DEST_CONFIG}"
elif [ ! -f "${DEST_CONFIG}" ]; then
    echo "==> Generating initial configuration"
    AGENT_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || echo "$(date +%s)-$(hostname)")"
    HOSTNAME="$(hostname)"

    cat > "${DEST_CONFIG}" <<YAML
# Auto-generated EDR agent configuration
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Agent ID: ${AGENT_ID}

agent:
  id: "${AGENT_ID}"
  name: "${HOSTNAME}"
  environment: "enterprise"
  log_level: "info"
  data_dir: "${DATA_DIR}"
  temp_dir: "/tmp/edr"

server:
  endpoint: ""
  grpc_port: 50051
  mutual_tls: true
  heartbeat_sec: 30
  reconnect_sec: 5
  airgap_mode: false

detection:
  sigma:
    enabled: true
    rules_dir: "${RULES_DIR}/sigma"
  yara:
    enabled: true
    rules_dir: "${RULES_DIR}/yara"
  ioc:
    enabled: true
    hash_db_path: "${DATA_DIR}/ioc/hashes.db"
    ip_db_path: "${DATA_DIR}/ioc/ips.db"
    domain_db_path: "${DATA_DIR}/ioc/domains.db"
  behavioral:
    baseline_days: 7
    sensitivity: "high"
    ransomware_detect: true
    rat_detect: true
    exfil_detect: true
    lateral_movement_detect: true

response:
  auto_response: true
  actions:
    kill_process: true
    quarantine_file: false
    network_isolate: false
    block_hash: false
    disable_user: false
    collect_forensics: false
    take_snapshot: false
  quarantine:
    dir: "${DATA_DIR}/quarantine"
  forensics:
    output_dir: "${DATA_DIR}/forensics"
    chain_of_custody: true

response_legacy:
  allow_kill: true
  auto_kill_enabled: true
  min_kill_score: 90
  kill_rule_allowlist: []
  protected_processes: []

self_protect:
  enabled: true
  watchdog: true
  integrity_check: true

performance:
  max_cpu_percent: 5
  max_memory_mb: 200
  event_buffer_size: 65536
  batch_size: 50
  batch_interval_ms: 15000

service:
  endpoint_id: "${AGENT_ID}"
  tick_interval: "1s"
  pid_file: "/var/run/edr-agent.pid"

logging:
  level: "info"
  alert_file: "${LOG_DIR}/alerts.jsonl"
  audit_file: "${LOG_DIR}/audit.jsonl"

rules_file: "rules/baseline.yaml"
YAML

    chmod 640 "${DEST_CONFIG}"
else
    echo "==> Config already exists at ${DEST_CONFIG}, skipping"
fi

echo "    ${DEST_CONFIG}"

# ---------- install rules ----------

if [ -d "${ROOT_DIR}/rules" ]; then
    echo "==> Installing detection rules"
    cp -r "${ROOT_DIR}/rules/"* "${RULES_DIR}/" 2>/dev/null || true
fi

# ---------- create service ----------

echo "==> Installing platform service"

case "${OS}" in
    linux)
        cat > /etc/systemd/system/edr-agent.service <<UNIT
[Unit]
Description=EDR Endpoint Detection and Response Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/edr-agent run --config ${DEST_CONFIG}
Restart=always
RestartSec=5
LimitNOFILE=65536
LimitMEMLOCK=infinity
WorkingDirectory=${DATA_DIR}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=edr-agent
ProtectSystem=strict
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

        systemctl daemon-reload
        systemctl enable edr-agent
        systemctl start edr-agent
        echo "    systemd service enabled and started"
        ;;

    darwin)
        cat > /Library/LaunchDaemons/com.razatech.edr-agent.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.razatech.edr-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_DIR}/edr-agent</string>
        <string>run</string>
        <string>--config</string>
        <string>${DEST_CONFIG}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/agent.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/agent.stderr.log</string>
</dict>
</plist>
PLIST

        launchctl load /Library/LaunchDaemons/com.razatech.edr-agent.plist
        echo "    LaunchDaemon loaded"
        ;;
esac

# ---------- done ----------

echo ""
echo "==> Installation complete"
echo "    Agent binary:  ${BIN_DIR}/edr-agent"
echo "    Config:        ${DEST_CONFIG}"
echo "    Data dir:      ${DATA_DIR}"
echo "    Log dir:       ${LOG_DIR}"
echo ""
echo "    Check status:  edrctl status"
echo "    View logs:     journalctl -u edr-agent -f  (Linux)"
echo "                   tail -f ${LOG_DIR}/agent.stdout.log  (macOS)"
