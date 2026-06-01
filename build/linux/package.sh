#!/usr/bin/env bash
set -euo pipefail
VERSION="${1:-dev}"
ARCH="${2:-amd64}"
BINARY="dist/linux-${ARCH}/edr-agent"
EDRCTL="bin/edrctl-linux-${ARCH}"
RULES_SRC="rules"
EBPF_OBJ="platform/linux/ebpf/edr.bpf.o"
EBPF_VER="internal/kernel/ebpf_expected_version.txt"

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
if [ ! -f "${EBPF_VER}" ]; then
    echo "missing eBPF version file: ${EBPF_VER} (run: make ebpf-link)" >&2
    exit 1
fi

mkdir -p pkg/deb/{DEBIAN,usr/bin,etc/edr-agent,lib/systemd/system,var/lib/edr-agent,var/lib/edr/bpf,usr/share/edr-agent/sqa}
cp "$BINARY" pkg/deb/usr/bin/edr-agent
chmod 755 pkg/deb/usr/bin/edr-agent
if [ -f "${EDRCTL}" ]; then
    cp "${EDRCTL}" pkg/deb/usr/bin/edrctl
    chmod 755 pkg/deb/usr/bin/edrctl
fi

cp configs/linux/config.yml pkg/deb/etc/edr-agent/config.yml
if [ -f configs/linux/config.enterprise.yml ]; then
    cp configs/linux/config.enterprise.yml pkg/deb/etc/edr-agent/config.enterprise.yml
fi
if [ -f configs/linux/config.fleet.yml ]; then
    cp configs/linux/config.fleet.yml pkg/deb/etc/edr-agent/config.fleet.yml
fi
if [ ! -d "${RULES_SRC}" ]; then
    echo "rules directory not found: ${RULES_SRC}" >&2
    exit 1
fi
mkdir -p pkg/deb/etc/edr-agent/rules
cp -R "${RULES_SRC}/." pkg/deb/etc/edr-agent/rules/
if [ -d models ] && compgen -G "models/*.onnx" >/dev/null; then
    mkdir -p pkg/deb/usr/share/edr-agent/models
    cp models/*.onnx pkg/deb/usr/share/edr-agent/models/
    [ -f models/manifest.json ] && cp models/manifest.json pkg/deb/usr/share/edr-agent/models/
    for sig in models/*.onnx.sig; do
        [ -f "${sig}" ] && cp "${sig}" pkg/deb/usr/share/edr-agent/models/
    done
fi
mkdir -p pkg/deb/var/lib/edr/bpf
cp "${EBPF_OBJ}" pkg/deb/var/lib/edr/bpf/edr.bpf.o
cp "${EBPF_VER}" pkg/deb/var/lib/edr/bpf/edr.bpf.version
for script in scripts/validate_on_device.sh scripts/sqa_simulations.sh; do
    if [ -f "${script}" ]; then
        cp "${script}" "pkg/deb/usr/share/edr-agent/sqa/$(basename "${script}")"
        chmod 755 "pkg/deb/usr/share/edr-agent/sqa/$(basename "${script}")"
    fi
done
cat > pkg/deb/usr/share/edr-agent/sqa/SQA_INSTALL.txt <<'TXT'
EDR SQA package for Kali Linux / Debian amd64

After install:
  systemctl status edr-agent --no-pager
  /usr/share/edr-agent/sqa/validate_on_device.sh /usr/bin/edr-agent /etc/edr-agent/config.yml
  /usr/share/edr-agent/sqa/sqa_simulations.sh

Artifacts:
  /var/lib/edr-agent/validation_report.json
  /var/lib/edr-agent/monitoring_report.json
  /var/lib/edr-agent/monitoring_health.json
  /var/lib/edr-agent/alerts.jsonl
TXT

cat > "pkg/deb/lib/systemd/system/edr-agent.service" << 'EOF'
[Unit]
Description=EDR Agent
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=/var/lib/edr-agent
ExecStart=/usr/bin/edr-agent --config /etc/edr-agent/config.yml --data-dir /var/lib/edr-agent
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
Depends: libc6, libyara10 | libyara9, systemd
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
dpkg-deb --root-owner-group --build pkg/deb "dist/edr-agent_${DEB_VERSION}_${ARCH}.deb"

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
