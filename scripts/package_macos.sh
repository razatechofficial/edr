#!/usr/bin/env bash
# Build a signed-style macOS .pkg that installs:
#   - edr-agent, edrctl (fat path: both arch binaries in payload)
#   - Bundled ONNX models under /Library/Application Support/EDR/models
#   - Full agent.yaml (from configs/agent.yaml) with install paths + ML enabled
#   - Detection rules under .../config/rules
#
# Prerequisites:
#   make build-darwin
#   Populate ./models with at least *.onnx (train or copy artifacts).
#
# Optional env:
#   AIRGAP=1          Set server.airgap_mode true in shipped config (default 1).
#   REQUIRE_MODELS=1  Fail if ./models has no .onnx (default 1).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

if ! command -v pkgbuild >/dev/null 2>&1 || ! command -v productbuild >/dev/null 2>&1; then
	echo "pkgbuild and productbuild are required (run on macOS with Xcode Command Line Tools)." >&2
	exit 1
fi

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0")}"
AIRGAP="${AIRGAP:-1}"
REQUIRE_MODELS="${REQUIRE_MODELS:-1}"

case "$(uname -m)" in
arm64) ARCH=arm64 ;;
x86_64) ARCH=amd64 ;;
*)
	echo "unsupported architecture: $(uname -m)" >&2
	exit 1
	;;
esac

if [[ "${ARCH}" == "amd64" ]]; then
	NEED_UNAME=x86_64
	NEED_LABEL="Intel (amd64)"
	OTHER_PKG="arm64 (Apple silicon)"
	HOST_ARCHS="x86_64"
	ARCH_TITLE="Intel"
else
	NEED_UNAME=arm64
	NEED_LABEL="Apple silicon (arm64)"
	OTHER_PKG="amd64 (Intel)"
	HOST_ARCHS="arm64"
	ARCH_TITLE="Apple silicon"
fi

REQUIRED_BINS=(
	bin/edr-agent-darwin-amd64
	bin/edr-agent-darwin-arm64
	bin/edrctl-darwin-amd64
	bin/edrctl-darwin-arm64
	bin/edr-agent-ui-darwin-amd64
	bin/edr-agent-ui-darwin-arm64
)
for f in "${REQUIRED_BINS[@]}"; do
	if [[ ! -f "${f}" ]]; then
		echo "missing required binary: ${f}" >&2
		exit 1
	fi
done

AGENT_BIN="bin/edr-agent-darwin-${ARCH}"
EDRCTL_BIN="bin/edrctl-darwin-${ARCH}"
UI_BIN="bin/edr-agent-ui-darwin-${ARCH}"

if [[ ! -f rules/baseline.yaml ]]; then
	echo "missing rules/baseline.yaml" >&2
	exit 1
fi

MODELS_SRC="${ROOT}/models"
if [[ "${REQUIRE_MODELS}" == "1" ]]; then
	if [[ ! -d "${MODELS_SRC}" ]]; then
		echo "missing directory: ${MODELS_SRC} (train models or set REQUIRE_MODELS=0)" >&2
		exit 1
	fi
	shopt -s nullglob
	ONNX_FILES=("${MODELS_SRC}"/*.onnx)
	shopt -u nullglob
	if [[ ${#ONNX_FILES[@]} -eq 0 ]]; then
		echo "no *.onnx in ${MODELS_SRC} — add trained models before packaging (or REQUIRE_MODELS=0)" >&2
		exit 1
	fi
fi

if [[ ! -f "${ROOT}/configs/agent.yaml" ]]; then
	echo "missing ${ROOT}/configs/agent.yaml" >&2
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
mkdir -p "${STAGE}/Library/Application Support/EDR/models"

cp "${AGENT_BIN}" "${STAGE}/usr/local/bin/edr-agent"
cp "${EDRCTL_BIN}" "${STAGE}/usr/local/bin/edrctl"
cp "${EDRCTL_BIN}" "${STAGE}/usr/local/bin/edr"
chmod 755 "${STAGE}/usr/local/bin/edr-agent" "${STAGE}/usr/local/bin/edrctl" "${STAGE}/usr/local/bin/edr"

INSTALLER_BIN="${ROOT}/bin/edr-installer-darwin-${ARCH}"
GOOS=darwin GOARCH="${ARCH}" bash "${ROOT}/scripts/ci/stage_embedded_installer.sh" \
	"${AGENT_BIN}" "${EDRCTL_BIN}" "${INSTALLER_BIN}"
mkdir -p "${STAGE}/Applications"
bash "${ROOT}/scripts/ci/macos_console_app.sh" "${UI_BIN}" "${EDRCTL_BIN}" "${STAGE}/Applications/EDR Agent.app" "${INSTALLER_BIN}"

cp "${ROOT}/deploy/macos/first-run-permissions.sh" "${STAGE}/Library/Application Support/EDR/first-run-permissions.sh"
chmod 755 "${STAGE}/Library/Application Support/EDR/first-run-permissions.sh"
mkdir -p "${STAGE}/Library/LaunchAgents"
cp "${ROOT}/deploy/macos/com.razatech.edr.firstrun.plist" "${STAGE}/Library/LaunchAgents/com.razatech.edr.firstrun.plist"
chmod 644 "${STAGE}/Library/LaunchAgents/com.razatech.edr.firstrun.plist"
cp "${ROOT}/deploy/macos/com.razatech.edr-agent-ui.plist" "${STAGE}/Library/LaunchAgents/com.razatech.edr-agent-ui.plist"
chmod 644 "${STAGE}/Library/LaunchAgents/com.razatech.edr-agent-ui.plist"

# Full rules tree (sigma, yara, baseline, …)
if [[ -d "${ROOT}/rules" ]]; then
	cp -R "${ROOT}/rules/." "${STAGE}/Library/Application Support/EDR/config/rules/"
fi

# Bundled ML artifacts (ONNX + optional signatures + manifest)
if [[ -d "${MODELS_SRC}" ]]; then
	shopt -s nullglob
	for f in "${MODELS_SRC}"/*.onnx "${MODELS_SRC}"/*.sig "${MODELS_SRC}"/*.onnx.sig "${MODELS_SRC}"/manifest.json "${MODELS_SRC}"/*.npy; do
		[[ -f "${f}" ]] || continue
		cp "${f}" "${STAGE}/Library/Application Support/EDR/models/"
	done
	shopt -u nullglob
	echo "==> Staged models from ${MODELS_SRC}"
	ls -la "${STAGE}/Library/Application Support/EDR/models"
fi

# Production agent config with absolute paths for a system install
EDR_BASE="/Library/Application Support/EDR"
RULES_BASELINE_ABS="${EDR_BASE}/config/rules/baseline.yaml"
CONFIG_DST="${STAGE}/Library/Application Support/EDR/config/agent.yaml"
sed \
	-e "s|data_dir: \"/var/lib/edr\"|data_dir: \"${EDR_BASE}\"|" \
	-e "s|models_dir: \"./models\"|models_dir: \"${EDR_BASE}/models\"|" \
	-e "s|^rules_file:.*|rules_file: \"${RULES_BASELINE_ABS}\"|" \
	"${ROOT}/configs/agent.yaml" > "${CONFIG_DST}"

if [[ "${AIRGAP}" == "1" ]]; then
	tmpf="$(mktemp)"
	sed 's|airgap_mode: false|airgap_mode: true|' "${CONFIG_DST}" > "${tmpf}" && mv "${tmpf}" "${CONFIG_DST}"
fi
chmod 640 "${CONFIG_DST}"

cat > "${SCRIPTS}/preinstall" <<PRE
#!/bin/bash
set -e
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
HOST="\$(uname -m)"
NEED_UNAME="${NEED_UNAME}"
if [[ "\${HOST}" != "\${NEED_UNAME}" ]]; then
	echo "This EDR Agent package is for ${NEED_LABEL} Macs. This Mac reports \${HOST}. Download the ${OTHER_PKG} package instead." >&2
	exit 1
fi
PLIST="/Library/LaunchDaemons/com.razatech.edr-agent.plist"
if launchctl print "system/com.razatech.edr-agent" &>/dev/null; then
	launchctl bootout system "\${PLIST}" 2>/dev/null || true
fi
launchctl unload "\${PLIST}" 2>/dev/null || true
if /usr/bin/pgrep -f "/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui" >/dev/null 2>&1; then
	/usr/bin/osascript -e 'tell application "EDR Agent" to quit' >/dev/null 2>&1 || true
	sleep 2
	if /usr/bin/pgrep -f "/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui" >/dev/null 2>&1; then
		echo "Quit EDR Agent, then run this package again to update or reinstall." >&2
		exit 1
	fi
fi
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

# Minimal fallback only if the package did not ship agent.yaml (first boot edge cases).
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
	chmod 640 "${CONFIG_FILE}"
fi

# Upgrades and reinstalls often preserve an existing agent.yaml; force the bundled
# rules layout path so we never run with a stale relative rules_file under launchd.
RULES_BASELINE="${CONFIG_DIR}/rules/baseline.yaml"
if [[ -f "${CONFIG_FILE}" ]]; then
	tmpf="$(mktemp "${TMPDIR:-/tmp}/edr-postinstall.XXXXXX")"
	sed "s|^rules_file:.*|rules_file: \"${RULES_BASELINE}\"|" "${CONFIG_FILE}" > "${tmpf}" && mv "${tmpf}" "${CONFIG_FILE}"
	chmod 640 "${CONFIG_FILE}"
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
		<string>run</string>
		<string>--config</string>
		<string>/Library/Application Support/EDR/config/agent.yaml</string>
	</array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
	<key>ThrottleInterval</key>
	<integer>30</integer>
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
# RunAtLoad is true so the next reboot starts the sensor for every user.
# Do not bootstrap during Installer.app — loading models hangs the pkg UI.
# Re-enrolled upgrades resume now; first install waits for EDR Agent.app.
if [[ -f "${BASE}/xdr-tls/enrollment.json" ]]; then
	launchctl bootstrap system "${PLIST_DST}" 2>/dev/null || launchctl load "${PLIST_DST}" 2>/dev/null || true
	launchctl enable "system/com.razatech.edr-agent" 2>/dev/null || true
	launchctl kickstart -k "system/com.razatech.edr-agent" 2>/dev/null || true
fi

UI_PLIST="/Library/LaunchAgents/com.razatech.edr-agent-ui.plist"

APP="/Applications/EDR Agent.app"
if [[ -d "${APP}" ]]; then
	LSREG="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	CONSOLE_USER="$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null || true)"
	if [[ -x "${LSREG}" ]]; then
		"${LSREG}" -f "${APP}" >/dev/null 2>&1 || true
	fi
	if [[ -n "${CONSOLE_USER}" && "${CONSOLE_USER}" != "root" && "${CONSOLE_USER}" != "loginwindow" ]]; then
		if [[ -x "${LSREG}" ]]; then
			/usr/bin/sudo -u "${CONSOLE_USER}" "${LSREG}" -f "${APP}" >/dev/null 2>&1 || true
		fi
		/usr/bin/sudo -u "${CONSOLE_USER}" /usr/bin/open "${APP}" >/dev/null 2>&1 || true
		if [[ -f "${UI_PLIST}" ]]; then
			UID_U="$(/usr/bin/id -u "${CONSOLE_USER}" 2>/dev/null || true)"
			if [[ -n "${UID_U}" ]]; then
				launchctl bootstrap "gui/${UID_U}" "${UI_PLIST}" 2>/dev/null || true
			fi
		fi
	fi
fi
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
	<title>EDR Agent (${ARCH_TITLE})</title>
	<domains enable_localSystem="true"/>
	<options customize="never" require-scripts="false" rootVolumeOnly="true" hostArchitectures="${HOST_ARCHS}"/>
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
