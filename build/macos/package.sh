#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:-dev}"
ARCH="${2:-arm64}"
BINARY="dist/darwin-${ARCH}/edr-agent"
if [ ! -f "${BINARY}" ] && [ -f "dist/darwin-${ARCH}-nosec/edr-agent" ]; then
  BINARY="dist/darwin-${ARCH}-nosec/edr-agent"
  echo "using nosec binary fallback: ${BINARY}"
fi

PKG_ROOT="pkg/macos/root"
mkdir -p \
    "${PKG_ROOT}/usr/local/bin" \
    "${PKG_ROOT}/Library/LaunchDaemons" \
    "${PKG_ROOT}/etc/edr-agent"

cp "$BINARY" "${PKG_ROOT}/usr/local/bin/edr-agent"
chmod 755 "${PKG_ROOT}/usr/local/bin/edr-agent"

cat > "${PKG_ROOT}/Library/LaunchDaemons/com.razatech.edr-agent.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.razatech.edr-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/edr-agent</string>
        <string>--config</string>
        <string>/etc/edr-agent/config.yml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/edr-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/edr-agent.error.log</string>
</dict>
</plist>
EOF

cp configs/macos/config.yml "${PKG_ROOT}/etc/edr-agent/config.yml"

mkdir -p pkg/macos/scripts

cat > pkg/macos/scripts/postinstall << 'EOF'
#!/bin/bash
launchctl load /Library/LaunchDaemons/com.razatech.edr-agent.plist
EOF
chmod 755 pkg/macos/scripts/postinstall

cat > pkg/macos/scripts/preinstall << 'EOF'
#!/bin/bash
launchctl unload /Library/LaunchDaemons/com.razatech.edr-agent.plist 2>/dev/null || true
EOF
chmod 755 pkg/macos/scripts/preinstall

mkdir -p dist
pkgbuild \
    --root "${PKG_ROOT}" \
    --scripts pkg/macos/scripts \
    --identifier com.razatech.edr-agent \
    --version "${VERSION}" \
    "dist/edr-agent_${VERSION}_${ARCH}.pkg"

echo "macOS package: dist/edr-agent_${VERSION}_${ARCH}.pkg"
