#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

if ! command -v pkgbuild >/dev/null 2>&1 || ! command -v productbuild >/dev/null 2>&1; then
	echo "pkgbuild and productbuild are required (run on macOS with Xcode Command Line Tools)." >&2
	exit 1
fi

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0")}"

case "$(uname -m)" in
arm64) ARCH=arm64 ;;
x86_64) ARCH=amd64 ;;
*)
	echo "unsupported architecture: $(uname -m)" >&2
	exit 1
	;;
esac

REQUIRED_BINS=(
	bin/edr-agent-darwin-amd64
	bin/edr-agent-darwin-arm64
	bin/edrctl-darwin-amd64
	bin/edrctl-darwin-arm64
)
for f in "${REQUIRED_BINS[@]}"; do
	if [[ ! -f "${f}" ]]; then
		echo "missing required binary: ${f}" >&2
		exit 1
	fi
done

AGENT_BIN="bin/edr-agent-darwin-${ARCH}"
EDRCTL_BIN="bin/edrctl-darwin-${ARCH}"

if [[ ! -f rules/baseline.yaml ]]; then
	echo "missing rules/baseline.yaml" >&2
	exit 1
fi

xml_escape() {
	printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

VER_XML="$(xml_escape "${VERSION}")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/edr-pkg.XXXXXX")"
STAGE="${WORK}/stage"
SCRIPTS="${WORK}/scripts"
mkdir -p "${STAGE}/usr/local/bin" "${SCRIPTS}"
mkdir -p "${STAGE}/Library/Application Support/EDR/config/rules"

cp "${AGENT_BIN}" "${STAGE}/usr/local/bin/edr-agent"
cp "${EDRCTL_BIN}" "${STAGE}/usr/local/bin/edrctl"
chmod 755 "${STAGE}/usr/local/bin/edr-agent" "${STAGE}/usr/local/bin/edrctl"
cp rules/baseline.yaml "${STAGE}/Library/Application Support/EDR/config/rules/baseline.yaml"

cat > "${SCRIPTS}/preinstall" <<'PRE'
#!/bin/bash
set -e
PLIST="/Library/LaunchDaemons/com.razatech.edr-agent.plist"
if launchctl print "system/com.razatech.edr-agent" &>/dev/null; then
	launchctl bootout system "${PLIST}" 2>/dev/null || true
fi
launchctl unload "${PLIST}" 2>/dev/null || true
PRE

cat > "${SCRIPTS}/postinstall" <<'POST'
#!/bin/bash
set -e
BASE="/Library/Application Support/EDR"
CONFIG_DIR="${BASE}/config"
CONFIG_FILE="${CONFIG_DIR}/agent.yaml"
LOG_DIR="/Library/Logs/EDR"
PLIST_DST="/Library/LaunchDaemons/com.razatech.edr-agent.plist"

mkdir -p "${CONFIG_DIR}" "${BASE}/alerts" "${LOG_DIR}"
chmod 755 "${BASE}" "${CONFIG_DIR}" 2>/dev/null || true

if [[ ! -f "${CONFIG_FILE}" ]]; then
	AGENT_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
	ENDPOINT_ID="$(scutil --get LocalHostName 2>/dev/null || hostname -s || hostname || echo "edr-endpoint")"
	RULES_PATH="${CONFIG_DIR}/rules/baseline.yaml"
	cat > "${CONFIG_FILE}" <<EOF
agent:
  id: "${AGENT_ID}"
  data_dir: "${BASE}"
  temp_dir: "/tmp/edr"
server:
  endpoint: ""
  grpc_port: 50051
service:
  endpoint_id: "${ENDPOINT_ID}"
  tick_interval: "1s"
  pid_file: "${BASE}/agent.pid"
rules_file: "${RULES_PATH}"
logging:
  level: "info"
  alert_file: "${BASE}/alerts/alerts.jsonl"
  audit_file: "${BASE}/alerts/audit.jsonl"
response:
  allow_kill: true
  auto_kill_enabled: false
  min_kill_score: 90
  kill_rule_allowlist:
    - "PROC-003"
    - "PROC-004"
    - "PROC-005"
    - "PROC-007"
    - "PROC-012"
  protected_processes:
    - "launchd"
    - "systemd"
forwarder:
  enabled: false
  mode: "http"
  endpoint: "http://localhost:8080/ingest"
  syslog_addr: "127.0.0.1:514"
  kafka_brokers: ["localhost:9092"]
  kafka_topic: "edr-alerts"
  retry_max: 3
  spool_path: "${BASE}/alerts/forward_spool.jsonl"
EOF
	chmod 644 "${CONFIG_FILE}"
fi

cat > "${PLIST_DST}" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.razatech.edr-agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/bin/edr-agent</string>
		<string>--config</string>
		<string>/Library/Application Support/EDR/config/agent.yaml</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/Library/Logs/EDR/stdout.log</string>
	<key>StandardErrorPath</key>
	<string>/Library/Logs/EDR/stderr.log</string>
</dict>
</plist>
PLIST
chmod 644 "${PLIST_DST}"
chown root:wheel "${PLIST_DST}"

launchctl bootout system "${PLIST_DST}" 2>/dev/null || true
launchctl unload "${PLIST_DST}" 2>/dev/null || true
launchctl bootstrap system "${PLIST_DST}"
launchctl enable "system/com.razatech.edr-agent" 2>/dev/null || true
POST

chmod 755 "${SCRIPTS}/preinstall" "${SCRIPTS}/postinstall"

COMPONENT="${WORK}/edr-component.pkg"
mkdir -p "${ROOT}/dist"

pkgbuild \
	--root "${STAGE}" \
	--scripts "${SCRIPTS}" \
	--identifier "com.razatech.edr-agent" \
	--version "${VERSION}" \
	--install-location "/" \
	--ownership recommended \
	"${COMPONENT}"

DIST_XML="${WORK}/distribution.xml"
cat > "${DIST_XML}" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
	<title>EDR Agent</title>
	<domains enable_localSystem="true"/>
	<options customize="never" require-scripts="false" rootVolumeOnly="true"/>
	<choices-outline>
		<line choice="com.razatech.edr-agent"/>
	</choices-outline>
	<choice id="com.razatech.edr-agent" visible="false">
		<pkg-ref id="com.razatech.edr-agent"/>
	</choice>
	<pkg-ref id="com.razatech.edr-agent" version="${VER_XML}" onConclusion="none">edr-component.pkg</pkg-ref>
</installer-gui-script>
EOF

OUT_SAFE_VER="${VERSION//\//-}"
OUT="${ROOT}/dist/edr-agent-${OUT_SAFE_VER}-darwin-${ARCH}.pkg"
productbuild --distribution "${DIST_XML}" --package-path "${WORK}" "${OUT}"

rm -rf "${WORK}"
echo "${OUT}"
