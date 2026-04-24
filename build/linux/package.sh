#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:-dev}"
ARCH="${2:-amd64}"
BINARY="dist/linux-${ARCH}/edr-agent"
RULES_SRC="rules"
EBPF_OBJ="platform/linux/ebpf/edr.bpf.o"

# Debian requires package version to start with a digit.
DEB_VERSION="${VERSION}"
if ! [[ "${DEB_VERSION}" =~ ^[0-9] ]]; then
    if [[ "${DEB_VERSION}" =~ ^v[0-9] ]]; then
        DEB_VERSION="${DEB_VERSION#v}"
    else
        DEB_VERSION="0.0.0-${DEB_VERSION}"
    fi
fi

if ! command -v dpkg-deb &>/dev/null; then
    echo "dpkg-deb not found; install dpkg-dev on Linux packaging host" >&2
    exit 1
fi
if [ ! -f "${BINARY}" ]; then
    echo "missing binary: ${BINARY} (run Linux build first)" >&2
    exit 1
fi
if [ ! -f "${EBPF_OBJ}" ]; then
    echo "missing eBPF object: ${EBPF_OBJ} (run: make ebpf && make ebpf-link)" >&2
    exit 1
fi

mkdir -p pkg/deb/{DEBIAN,usr/bin,etc/edr-agent,lib/systemd/system,var/lib/edr-agent}
cp "$BINARY" pkg/deb/usr/bin/edr-agent
chmod 755 pkg/deb/usr/bin/edr-agent

cp configs/linux/config.yml pkg/deb/etc/edr-agent/config.yml
if [ ! -d "${RULES_SRC}" ]; then
    echo "rules directory not found: ${RULES_SRC}" >&2
    exit 1
fi
mkdir -p pkg/deb/etc/edr-agent/rules
cp -R "${RULES_SRC}/." pkg/deb/etc/edr-agent/rules/
mkdir -p pkg/deb/var/lib/edr/bpf
cp "${EBPF_OBJ}" pkg/deb/var/lib/edr/bpf/edr.bpf.o

cat > "pkg/deb/lib/systemd/system/edr-agent.service" << 'EOF'
[Unit]
Description=EDR Agent
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=/etc/edr-agent
ExecStart=/usr/bin/edr-agent --config /etc/edr-agent/config.yml
Restart=always
RestartSec=5
User=root
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

cat > pkg/deb/DEBIAN/control << EOF
Package: edr-agent
Version: ${DEB_VERSION}
Architecture: ${ARCH}
Maintainer: Raza Tech <security@razatech.com>
Description: EDR Agent
 Endpoint Detection and Response agent.
Depends: libc6
EOF

cat > pkg/deb/DEBIAN/postinst << 'EOF'
#!/bin/bash
set -e
mkdir -p /var/lib/edr-agent /var/lib/edr-agent/forensics /var/lib/edr-agent/quarantine /var/lib/edr-agent/alert-spool
mkdir -p /etc/edr-agent/rules
mkdir -p /var/lib/edr/bpf
chmod 700 /var/lib/edr-agent /var/lib/edr-agent/forensics /var/lib/edr-agent/quarantine /var/lib/edr-agent/alert-spool
chmod 755 /etc/edr-agent /etc/edr-agent/rules
systemctl daemon-reload
systemctl enable edr-agent
systemctl start edr-agent
EOF
chmod 755 pkg/deb/DEBIAN/postinst

cat > pkg/deb/DEBIAN/prerm << 'EOF'
#!/bin/bash
set -e
systemctl stop edr-agent || true
systemctl disable edr-agent || true
EOF
chmod 755 pkg/deb/DEBIAN/prerm

mkdir -p dist
dpkg-deb --build pkg/deb "dist/edr-agent_${DEB_VERSION}_${ARCH}.deb"

mkdir -p build/linux
cp pkg/deb/DEBIAN/postinst build/linux/postinst.sh
cp pkg/deb/DEBIAN/prerm build/linux/prerm.sh

if command -v fpm &>/dev/null; then
    fpm -s dir -t rpm \
        -n edr-agent -v "${VERSION}" \
        --prefix / \
        --after-install build/linux/postinst.sh \
        --before-remove build/linux/prerm.sh \
        pkg/deb/usr/bin/edr-agent=/usr/bin/edr-agent \
        pkg/deb/etc/edr-agent/=/etc/edr-agent/ \
        "pkg/deb/lib/systemd/system/edr-agent.service=/lib/systemd/system/edr-agent.service"
    mv ./*.rpm dist/
fi

echo "Packages built in dist/"
