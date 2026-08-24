#!/usr/bin/env bash
# Lightweight macOS .pkg builder (dev/CI). Production packaging uses scripts/package_macos.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${ROOT}"

VERSION="${1:-dev}"
ARCH="${2:-arm64}"
APP_BUNDLE="dist/edr-agent-${ARCH}.app"
BINARY="dist/darwin-${ARCH}/edr-agent"
if [[ -d "${APP_BUNDLE}/Contents/MacOS" && -f "${APP_BUNDLE}/Contents/MacOS/edr-agent" ]]; then
	:
elif [[ -d "dist/edr-agent.app/Contents/MacOS" && -f "dist/edr-agent.app/Contents/MacOS/edr-agent" ]]; then
	APP_BUNDLE="dist/edr-agent.app"
elif [[ -f "${BINARY}" ]]; then
	echo "warning: ${APP_BUNDLE} missing; packaging unsigned binary only (ES entitlement will not work)" >&2
else
	if [[ -f "dist/darwin-${ARCH}-nosec/edr-agent" ]]; then
		BINARY="dist/darwin-${ARCH}-nosec/edr-agent"
		echo "using nosec binary fallback: ${BINARY}"
	else
		echo "missing ${APP_BUNDLE} or ${BINARY}; run build_macos_production.sh first" >&2
		exit 1
	fi
fi
if [[ ! -f configs/agent.yaml ]]; then
	echo "missing configs/agent.yaml" >&2
	exit 1
fi

UI_BIN="bin/edr-agent-ui-darwin-${ARCH}"
CTL_BIN="bin/edrctl-darwin-${ARCH}"
if [[ ! -f "${UI_BIN}" ]]; then
	echo "missing ${UI_BIN}; run build_macos_production.sh first" >&2
	exit 1
fi
if [[ ! -f "${CTL_BIN}" ]]; then
	echo "missing ${CTL_BIN}; run build_macos_production.sh first" >&2
	exit 1
fi

EDR_BASE="/Library/Application Support/EDR"
RULES_BASELINE="${EDR_BASE}/config/rules/baseline.yaml"
PKG_ROOT="pkg/macos/root"

rm -rf "${PKG_ROOT}/etc/edr-agent" "${PKG_ROOT}/usr/local/libexec" "${PKG_ROOT}/Applications"
AGENT_APP="/usr/local/libexec/edr-agent.app"
AGENT_BIN="${AGENT_APP}/Contents/MacOS/edr-agent"

mkdir -p \
	"${PKG_ROOT}/usr/local/libexec" \
	"${PKG_ROOT}/usr/local/bin" \
	"${PKG_ROOT}/Applications" \
	"${PKG_ROOT}/Library/LaunchDaemons" \
	"${PKG_ROOT}/Library/Application Support/EDR/config/rules" \
	"${PKG_ROOT}/Library/Application Support/EDR/models" \
	"${PKG_ROOT}/Library/Logs/EDR"

if [[ -d "${APP_BUNDLE}/Contents" ]]; then
	cp -R "${APP_BUNDLE}" "${PKG_ROOT}/usr/local/libexec/edr-agent.app"
	chmod -R 755 "${PKG_ROOT}/usr/local/libexec/edr-agent.app"
elif [[ -f "${BINARY}" ]]; then
	mkdir -p "${PKG_ROOT}/usr/local/bin"
	cp "${BINARY}" "${PKG_ROOT}/usr/local/bin/edr-agent"
	chmod 755 "${PKG_ROOT}/usr/local/bin/edr-agent"
	AGENT_BIN="/usr/local/bin/edr-agent"
fi

cp "${CTL_BIN}" "${PKG_ROOT}/usr/local/bin/edrctl"
cp "${CTL_BIN}" "${PKG_ROOT}/usr/local/bin/edr"
chmod 755 "${PKG_ROOT}/usr/local/bin/edrctl" "${PKG_ROOT}/usr/local/bin/edr"

bash "${ROOT}/scripts/ci/macos_console_app.sh" "${UI_BIN}" "${CTL_BIN}" "${PKG_ROOT}/Applications/EDR Agent.app"

if [[ -f "${ROOT}/deploy/macos/first-run-permissions.sh" ]]; then
	cp "${ROOT}/deploy/macos/first-run-permissions.sh" "${PKG_ROOT}/Library/Application Support/EDR/first-run-permissions.sh"
	chmod 755 "${PKG_ROOT}/Library/Application Support/EDR/first-run-permissions.sh"
fi

if [[ -d rules ]]; then
	cp -R rules/. "${PKG_ROOT}/Library/Application Support/EDR/config/rules/"
fi

bash "${ROOT}/scripts/ci/ensure_onnx_models.sh"
if [[ -d models ]] && compgen -G "models/*.onnx" >/dev/null; then
	cp models/*.onnx "${PKG_ROOT}/Library/Application Support/EDR/models/"
	[[ -f models/manifest.json ]] && cp models/manifest.json "${PKG_ROOT}/Library/Application Support/EDR/models/"
	for sig in models/*.onnx.sig; do
		[[ -f "${sig}" ]] && cp "${sig}" "${PKG_ROOT}/Library/Application Support/EDR/models/"
	done
else
	echo "ERROR: ML models not found in models/ directory. Run 'make models-bootstrap' first." >&2
	exit 1
fi

if [[ -f configs/macos/config.enterprise.yml ]]; then
	cp configs/macos/config.enterprise.yml "${PKG_ROOT}/Library/Application Support/EDR/config/config.enterprise.yml"
fi
if [[ -f configs/macos/config.fleet.yml ]]; then
	cp configs/macos/config.fleet.yml "${PKG_ROOT}/Library/Application Support/EDR/config/config.fleet.yml"
fi
if [[ -f configs/macos/config.tenant.yml ]]; then
	cp configs/macos/config.tenant.yml "${PKG_ROOT}/Library/Application Support/EDR/config/config.tenant.yml"
fi
if [[ -f configs/macos/config.tenant.tls.yml ]]; then
	cp configs/macos/config.tenant.tls.yml "${PKG_ROOT}/Library/Application Support/EDR/config/config.tenant.tls.yml"
fi
if [[ -f configs/macos/config.fleet.tls.yml ]]; then
	cp configs/macos/config.fleet.tls.yml "${PKG_ROOT}/Library/Application Support/EDR/config/config.fleet.tls.yml"
fi

CONFIG_DST="${PKG_ROOT}/Library/Application Support/EDR/config/agent.yaml"
sed \
	-e "s|data_dir: \"/var/lib/edr\"|data_dir: \"${EDR_BASE}\"|" \
	-e "s|models_dir: \"./models\"|models_dir: \"${EDR_BASE}/models\"|" \
	-e "s|^rules_file:.*|rules_file: \"${RULES_BASELINE}\"|" \
	configs/agent.yaml > "${CONFIG_DST}"
chmod 640 "${CONFIG_DST}"

cat > "${PKG_ROOT}/Library/LaunchDaemons/com.razatech.edr-agent.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.razatech.edr-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent</string>
        <string>run</string>
        <string>--config</string>
        <string>/Library/Application Support/EDR/config/agent.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>StandardOutPath</key>
    <string>/Library/Logs/EDR/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/EDR/stderr.log</string>
</dict>
</plist>
EOF

mkdir -p pkg/macos/scripts

cat > pkg/macos/scripts/postinstall <<'EOF'
#!/bin/bash
set -e
BASE="/Library/Application Support/EDR"
CONFIG_DIR="${BASE}/config"
CONFIG_FILE="${CONFIG_DIR}/agent.yaml"
LOG_DIR="/Library/Logs/EDR"
PLIST="/Library/LaunchDaemons/com.razatech.edr-agent.plist"
RULES_BASELINE="${CONFIG_DIR}/rules/baseline.yaml"

mkdir -p "${CONFIG_DIR}" "${BASE}/alerts" "${BASE}/models" "${LOG_DIR}"
chmod 755 "${BASE}" "${CONFIG_DIR}" 2>/dev/null || true

if [[ -f "${CONFIG_FILE}" ]]; then
	tmpf="$(mktemp "${TMPDIR:-/tmp}/edr-postinstall.XXXXXX")"
	sed "s|^rules_file:.*|rules_file: \"${RULES_BASELINE}\"|" "${CONFIG_FILE}" > "${tmpf}" && mv "${tmpf}" "${CONFIG_FILE}"
	chmod 644 "${CONFIG_FILE}"
fi

launchctl bootout system "${PLIST}" 2>/dev/null || true
launchctl unload "${PLIST}" 2>/dev/null || true
if [[ -x "/usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent" ]]; then
	ln -sf "../libexec/edr-agent.app/Contents/MacOS/edr-agent" /usr/local/bin/edr-agent
fi
if [[ -d "/Applications/EDR Agent.app" ]]; then
	LSREG="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	if [[ -x "${LSREG}" ]]; then
		"${LSREG}" -f "/Applications/EDR Agent.app" >/dev/null 2>&1 || true
	fi
fi
launchctl bootstrap system "${PLIST}" 2>/dev/null || launchctl load "${PLIST}"
launchctl enable "system/com.razatech.edr-agent" 2>/dev/null || true
EOF
chmod 755 pkg/macos/scripts/postinstall

cat > pkg/macos/scripts/preinstall <<'EOF'
#!/bin/bash
set -e
PLIST="/Library/LaunchDaemons/com.razatech.edr-agent.plist"
if launchctl print "system/com.razatech.edr-agent" &>/dev/null; then
	launchctl bootout system "${PLIST}" 2>/dev/null || true
fi
launchctl unload "${PLIST}" 2>/dev/null || true
EOF
chmod 755 pkg/macos/scripts/preinstall

mkdir -p dist
pkgbuild \
	--root "${PKG_ROOT}" \
	--scripts pkg/macos/scripts \
	--identifier com.razatech.edr-agent \
	--version "${VERSION}" \
	--install-location "/" \
	"dist/edr-agent_${VERSION}_${ARCH}.pkg"

echo "macOS package: dist/edr-agent_${VERSION}_${ARCH}.pkg"
