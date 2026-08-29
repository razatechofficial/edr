#!/usr/bin/env bash
# macOS .pkg builder (release CI).
# Default EDR_PKG_MODE=attended: the pkg only drops EDR Agent.app (UI +
# embedded installer). Apple Installer authenticates; our wizard is license
# → copy files → enroll → dashboard.
# EDR_PKG_MODE=fleet EDR_PKG_SUFFIX=-mdm: also ships LaunchDaemon + models
# for MDM. Silent: /Applications/EDR Agent.app/Contents/MacOS/edr-installer install
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
PKG_MODE="${EDR_PKG_MODE:-attended}"
PKG_SUFFIX="${EDR_PKG_SUFFIX:-}"
if [[ ! -f "${UI_BIN}" ]]; then
	echo "missing ${UI_BIN}; run build_macos_production.sh first" >&2
	exit 1
fi
if [[ ! -f "${CTL_BIN}" ]]; then
	echo "missing ${CTL_BIN}; run build_macos_production.sh first" >&2
	exit 1
fi

# One .app holds the wizard through the dashboard. The privileged installer
# embeds agent + models + rules so testers do not need a zip of loose binaries.
INSTALLER_BIN="bin/edr-installer-darwin-${ARCH}"
AGENT_FOR_EMBED=""
if [[ -f "${APP_BUNDLE}/Contents/MacOS/edr-agent" ]]; then
	AGENT_FOR_EMBED="${APP_BUNDLE}/Contents/MacOS/edr-agent"
elif [[ -f "${BINARY}" ]]; then
	AGENT_FOR_EMBED="${BINARY}"
fi
if [[ -n "${AGENT_FOR_EMBED}" ]]; then
	GOOS=darwin GOARCH="${ARCH}" bash "${ROOT}/scripts/ci/stage_embedded_installer.sh" \
		"${AGENT_FOR_EMBED}" "${CTL_BIN}" "${INSTALLER_BIN}"
	if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
		codesign --force --options runtime --timestamp --sign "${APPLE_SIGN_IDENTITY}" "${INSTALLER_BIN}" || true
	fi
fi
if [[ ! -f "${INSTALLER_BIN}" ]]; then
	echo "missing ${INSTALLER_BIN}; attended setup needs the embedded installer" >&2
	exit 1
fi

EDR_BASE="/Library/Application Support/EDR"
RULES_BASELINE="${EDR_BASE}/config/rules/baseline.yaml"
# Separate roots so attended cannot pick up a leftover Intel/Homebrew sensor
# from a previous fleet staging pass (or a dirty runner workspace).
PKG_ROOT="pkg/macos/root-${PKG_MODE}"
rm -rf "${PKG_ROOT}"
AGENT_APP="/usr/local/libexec/edr-agent.app"
AGENT_BIN="${AGENT_APP}/Contents/MacOS/edr-agent"

mkdir -p "${PKG_ROOT}/Applications"

if [[ "${PKG_MODE}" == "fleet" ]]; then
mkdir -p \
	"${PKG_ROOT}/usr/local/libexec" \
	"${PKG_ROOT}/usr/local/bin" \
	"${PKG_ROOT}/Library/LaunchDaemons" \
	"${PKG_ROOT}/Library/Application Support/EDR/config/rules" \
	"${PKG_ROOT}/Library/Application Support/EDR/models" \
	"${PKG_ROOT}/Library/Logs/EDR"

if [[ -d "${APP_BUNDLE}/Contents" ]]; then
	rm -rf "${PKG_ROOT}/usr/local/libexec/edr-agent.app"
	# ditto preserves code signatures; chmod/touch after signing invalidates them
	# and Apple notarization rejects the binary.
	if command -v ditto >/dev/null 2>&1; then
		ditto "${APP_BUNDLE}" "${PKG_ROOT}/usr/local/libexec/edr-agent.app"
	else
		cp -a "${APP_BUNDLE}" "${PKG_ROOT}/usr/local/libexec/edr-agent.app"
	fi
	if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
		AGENT_APP_DST="${PKG_ROOT}/usr/local/libexec/edr-agent.app"
		FRAMEWORKS="${AGENT_APP_DST}/Contents/Frameworks"
		ENT="${ROOT}/build/macos/edr-agent.entitlements.plist"
		for dylib in "${FRAMEWORKS}"/*.dylib; do
			[[ -f "${dylib}" ]] || continue
			codesign --force --options runtime --timestamp --sign "${APPLE_SIGN_IDENTITY}" "${dylib}"
		done
		codesign --force --options runtime --timestamp \
			--entitlements "${ENT}" \
			--sign "${APPLE_SIGN_IDENTITY}" "${AGENT_APP_DST}/Contents/MacOS/edr-agent"
		codesign --force --options runtime --timestamp \
			--preserve-metadata=entitlements,flags,runtime \
			--sign "${APPLE_SIGN_IDENTITY}" "${AGENT_APP_DST}"
		codesign --verify --deep --strict "${AGENT_APP_DST}"
	fi
elif [[ -f "${BINARY}" ]]; then
	mkdir -p "${PKG_ROOT}/usr/local/bin"
	cp "${BINARY}" "${PKG_ROOT}/usr/local/bin/edr-agent"
	chmod 755 "${PKG_ROOT}/usr/local/bin/edr-agent"
	AGENT_BIN="/usr/local/bin/edr-agent"
fi

cp "${CTL_BIN}" "${PKG_ROOT}/usr/local/bin/edrctl"
cp "${CTL_BIN}" "${PKG_ROOT}/usr/local/bin/edr"
chmod 755 "${PKG_ROOT}/usr/local/bin/edrctl" "${PKG_ROOT}/usr/local/bin/edr"
if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
	codesign --force --options runtime --timestamp --sign "${APPLE_SIGN_IDENTITY}" "${PKG_ROOT}/usr/local/bin/edrctl"
	codesign --force --options runtime --timestamp --sign "${APPLE_SIGN_IDENTITY}" "${PKG_ROOT}/usr/local/bin/edr"
fi
fi

bash "${ROOT}/scripts/ci/macos_console_app.sh" "${UI_BIN}" "${CTL_BIN}" "${PKG_ROOT}/Applications/EDR Agent.app" "${INSTALLER_BIN}"

if [[ "${PKG_MODE}" == "fleet" ]]; then
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
EOF
fi

mkdir -p pkg/macos/scripts

# Attended: Apple Installer only drops EDR Agent.app. The Fyne wizard copies
# the sensor on Accept and continues through enroll to the dashboard.
# Fleet: files are already on disk; still do not start the daemon — Launch does.
cat > pkg/macos/scripts/postinstall <<'EOF'
#!/bin/bash
set -e
APP="/Applications/EDR Agent.app"
if [[ ! -d "${APP}" ]]; then
	exit 0
fi
LSREG="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
CONSOLE_USER="$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null || true)"
if [[ -x "${LSREG}" ]]; then
	"${LSREG}" -f "${APP}" >/dev/null 2>&1 || true
fi
if [[ -n "${CONSOLE_USER}" && "${CONSOLE_USER}" != "root" && "${CONSOLE_USER}" != "loginwindow" ]]; then
	/usr/bin/sudo -u "${CONSOLE_USER}" /usr/bin/open "${APP}" >/dev/null 2>&1 || true
fi
EOF
chmod 755 pkg/macos/scripts/postinstall

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

cat > pkg/macos/scripts/preinstall <<EOF
#!/bin/bash
set -e
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
HOST="\$(uname -m)"
if [[ "\${HOST}" != "${NEED_UNAME}" ]]; then
	MSG="This EDR Agent package is for ${NEED_LABEL} Macs. This Mac reports \${HOST}. Download the ${OTHER_PKG} package instead."
	echo "\${MSG}" >&2
	osascript -e "display dialog \"\${MSG}\" buttons {\"OK\"} default button \"OK\" with title \"EDR Agent\"" >/dev/null 2>&1 || true
	exit 1
fi
EOF
chmod 755 pkg/macos/scripts/preinstall

mkdir -p dist pkg/macos
COMPONENT="pkg/macos/edr-agent-component-${PKG_MODE}.pkg"
pkgbuild \
	--root "${PKG_ROOT}" \
	--scripts pkg/macos/scripts \
	--identifier com.razatech.edr-agent \
	--version "${VERSION}" \
	--install-location "/" \
	"${COMPONENT}"

DIST_XML="pkg/macos/distribution.xml"
# No welcome/license pages: Installer.app only authenticates and copies the
# .app. License + copy-files + enroll + dashboard live in EDR Agent.app.
cat > "${DIST_XML}" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
	<title>EDR Agent (${ARCH_TITLE})</title>
	<domains enable_localSystem="true"/>
	<options customize="never" require-scripts="false" hostArchitectures="${HOST_ARCHS}"/>
	<choices-outline>
		<line choice="com.razatech.edr-agent"/>
	</choices-outline>
	<choice id="com.razatech.edr-agent" visible="false">
		<pkg-ref id="com.razatech.edr-agent"/>
	</choice>
	<pkg-ref id="com.razatech.edr-agent" version="${VERSION}" onConclusion="none">edr-agent-component.pkg</pkg-ref>
</installer-gui-script>
EOF

PKG_OUT="dist/edr-agent_${VERSION}_${ARCH}${PKG_SUFFIX}.pkg"
productbuild \
	--distribution "${DIST_XML}" \
	--package-path pkg/macos \
	"${PKG_OUT}"

echo "macOS package: ${PKG_OUT} (${ARCH_TITLE}, ${PKG_MODE})"
