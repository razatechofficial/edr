#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

AGENT_BIN="${ROOT}/bin/edr-agent-linux-amd64"
EDRCTL_BIN="${ROOT}/bin/edrctl-linux-amd64"
CONFIG_SRC="${ROOT}/configs/agent.yaml"

for f in "${AGENT_BIN}" "${EDRCTL_BIN}" "${CONFIG_SRC}"; do
	if [[ ! -f "${f}" ]]; then
		echo "missing required file: ${f}" >&2
		exit 1
	fi
done

if ! command -v dpkg-deb >/dev/null 2>&1; then
	echo "dpkg-deb is required (Debian/Ubuntu packaging tools)." >&2
	exit 1
fi

RAW_VER="${EDR_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0")}"
VERSION="${RAW_VER#v}"
VERSION_RPM="${VERSION//-/~}"

mkdir -p "${ROOT}/dist"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/edr-linux-pkg.XXXXXX")"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

DEB_ROOT="${WORK}/deb"
mkdir -p "${DEB_ROOT}/DEBIAN" "${DEB_ROOT}/usr/local/bin" "${DEB_ROOT}/etc/edr" "${DEB_ROOT}/etc/systemd/system"
mkdir -p "${DEB_ROOT}/usr/share/edr/rules/sigma" "${DEB_ROOT}/usr/share/edr/rules/yara" "${DEB_ROOT}/usr/share/edr/rules/custom" "${DEB_ROOT}/usr/share/edr/models"

cp "${AGENT_BIN}" "${DEB_ROOT}/usr/local/bin/edr-agent"
cp "${EDRCTL_BIN}" "${DEB_ROOT}/usr/local/bin/edrctl"
chmod 0755 "${DEB_ROOT}/usr/local/bin/edr-agent" "${DEB_ROOT}/usr/local/bin/edrctl"
cp "${CONFIG_SRC}" "${DEB_ROOT}/etc/edr/agent.yaml.default"
chmod 0644 "${DEB_ROOT}/etc/edr/agent.yaml.default"

if [[ -d "${ROOT}/rules/sigma" ]]; then
	cp -a "${ROOT}/rules/sigma/." "${DEB_ROOT}/usr/share/edr/rules/sigma/"
fi
if [[ -d "${ROOT}/rules/yara" ]]; then
	cp -a "${ROOT}/rules/yara/." "${DEB_ROOT}/usr/share/edr/rules/yara/"
fi
if [[ -d "${ROOT}/rules/custom" ]]; then
	cp -a "${ROOT}/rules/custom/." "${DEB_ROOT}/usr/share/edr/rules/custom/"
fi
if [[ -f "${ROOT}/rules/baseline.yaml" ]]; then
	cp "${ROOT}/rules/baseline.yaml" "${DEB_ROOT}/usr/share/edr/rules/baseline.yaml"
fi
shopt -s nullglob
for f in "${ROOT}/models/"*.onnx; do
	cp -a "${f}" "${DEB_ROOT}/usr/share/edr/models/"
done
for f in "${ROOT}/models/"*.sig; do
	cp -a "${f}" "${DEB_ROOT}/usr/share/edr/models/"
done
shopt -u nullglob

cat > "${DEB_ROOT}/etc/systemd/system/edr-agent.service" <<'UNIT'
[Unit]
Description=EDR Endpoint Detection and Response Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edr-agent run --config /etc/edr/agent.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536
LimitMEMLOCK=infinity
WorkingDirectory=/var/lib/edr
StandardOutput=journal
StandardError=journal
SyslogIdentifier=edr-agent
ProtectSystem=strict
ReadWritePaths=/var/lib/edr /var/log/edr
PrivateTmp=true
NoNewPrivileges=false
ProtectKernelModules=false
ProtectKernelTunables=false
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_KILL
AmbientCapabilities=CAP_SYS_PTRACE CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_KILL

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "${DEB_ROOT}/etc/systemd/system/edr-agent.service"

INSTALLED_SIZE="$(du -sk "${DEB_ROOT}/usr" "${DEB_ROOT}/etc" 2>/dev/null | awk '{s+=$1} END {print s+0}')"

cat > "${DEB_ROOT}/DEBIAN/control" <<EOF
Package: edr-agent
Version: ${VERSION}
Architecture: amd64
Maintainer: RazaTech
Installed-Size: ${INSTALLED_SIZE}
Priority: optional
Section: utils
Description: EDR Endpoint Detection and Response Agent
EOF

cat > "${DEB_ROOT}/DEBIAN/preinst" <<'PRE'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl stop edr-agent 2>/dev/null || true
fi
exit 0
PRE

cat > "${DEB_ROOT}/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
mkdir -p /var/lib/edr /var/log/edr /etc/edr/rules /tmp/edr
chmod 0755 /var/lib/edr /var/log/edr /etc/edr/rules /tmp/edr || true
if [ ! -f /etc/edr/agent.yaml ]; then
	AGENT_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
	if [ -z "${AGENT_ID}" ]; then
		AGENT_ID="$(command -v uuidgen >/dev/null 2>&1 && uuidgen | tr '[:upper:]' '[:lower:]')"
	fi
	if [ -z "${AGENT_ID}" ] && command -v python3 >/dev/null 2>&1; then
		AGENT_ID="$(python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || true)"
	fi
	if [ -z "${AGENT_ID}" ]; then
		AGENT_ID="$(date +%s)-$(hostname)"
	fi
	cp /etc/edr/agent.yaml.default /etc/edr/agent.yaml
	sed -i "s|^  id: \"\"$|  id: \"${AGENT_ID}\"|" /etc/edr/agent.yaml || true
	chmod 0640 /etc/edr/agent.yaml
fi
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl daemon-reload
	systemctl enable edr-agent
	systemctl start edr-agent
fi
exit 0
POST

cat > "${DEB_ROOT}/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl stop edr-agent 2>/dev/null || true
fi
exit 0
PRERM

cat > "${DEB_ROOT}/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
case "$1" in
	remove|purge)
		if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
			systemctl disable edr-agent 2>/dev/null || true
			rm -f /etc/systemd/system/edr-agent.service
			systemctl daemon-reload 2>/dev/null || true
		fi
		;;
esac
exit 0
POSTRM

chmod 0755 "${DEB_ROOT}/DEBIAN/preinst" "${DEB_ROOT}/DEBIAN/postinst" "${DEB_ROOT}/DEBIAN/prerm" "${DEB_ROOT}/DEBIAN/postrm"

DEB_OUT="${ROOT}/dist/edr-agent-${VERSION}-linux-amd64.deb"
RPM_OUT="${ROOT}/dist/edr-agent-${VERSION}-linux-amd64.rpm"

dpkg-deb --root-owner-group -Zgzip -b "${DEB_ROOT}" "${DEB_OUT}"
echo "wrote ${DEB_OUT}"

if command -v fpm >/dev/null 2>&1; then
	fpm -f -s deb -t rpm -p "${RPM_OUT}" "${DEB_OUT}"
	echo "wrote ${RPM_OUT}"
	exit 0
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
	echo "error: fpm or rpmbuild is required to build the .rpm" >&2
	exit 1
fi

RPM_TOP="${WORK}/rpmbuild"
mkdir -p "${RPM_TOP}/"{BUILD,RPMS/noarch,RPMS/x86_64,SOURCES,SPECS,SRPMS}

PAYLOAD_NAME="edr-agent-${VERSION_RPM}"
PAYLOAD_ROOT="${WORK}/rpm-src/${PAYLOAD_NAME}"
mkdir -p "${PAYLOAD_ROOT}/usr/local/bin" "${PAYLOAD_ROOT}/etc/edr" "${PAYLOAD_ROOT}/etc/systemd/system"
mkdir -p "${PAYLOAD_ROOT}/usr/share/edr/rules/sigma" "${PAYLOAD_ROOT}/usr/share/edr/rules/yara" "${PAYLOAD_ROOT}/usr/share/edr/rules/custom" "${PAYLOAD_ROOT}/usr/share/edr/models"
cp "${AGENT_BIN}" "${PAYLOAD_ROOT}/usr/local/bin/edr-agent"
cp "${EDRCTL_BIN}" "${PAYLOAD_ROOT}/usr/local/bin/edrctl"
chmod 0755 "${PAYLOAD_ROOT}/usr/local/bin/edr-agent" "${PAYLOAD_ROOT}/usr/local/bin/edrctl"
cp "${CONFIG_SRC}" "${PAYLOAD_ROOT}/etc/edr/agent.yaml.default"
chmod 0644 "${PAYLOAD_ROOT}/etc/edr/agent.yaml.default"
cp -a "${DEB_ROOT}/usr/share/edr/." "${PAYLOAD_ROOT}/usr/share/edr/"
cp "${DEB_ROOT}/etc/systemd/system/edr-agent.service" "${PAYLOAD_ROOT}/etc/systemd/system/edr-agent.service"
chmod 0644 "${PAYLOAD_ROOT}/etc/systemd/system/edr-agent.service"

tar -czf "${RPM_TOP}/SOURCES/${PAYLOAD_NAME}.tar.gz" -C "${WORK}/rpm-src" "${PAYLOAD_NAME}"

cat > "${RPM_TOP}/SPECS/edr-agent.spec" <<SPECEOF
Summary: EDR Endpoint Detection and Response Agent
Name: edr-agent
Version: ${VERSION_RPM}
Release: 1%{?dist}
License: Proprietary
BuildArch: x86_64

Source0: %{name}-%{version}.tar.gz

%description
EDR Endpoint Detection and Response Agent.

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a %{_builddir}/%{name}-%{version}/* %{buildroot}/

%pre
case "\$1" in
	1|2)
		if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
			systemctl stop edr-agent 2>/dev/null || :
		fi
		;;
esac

%post
mkdir -p /var/lib/edr /var/log/edr /etc/edr/rules /tmp/edr
chmod 0755 /var/lib/edr /var/log/edr /etc/edr/rules /tmp/edr || :
if [ ! -f /etc/edr/agent.yaml ]; then
	AGENT_ID="\$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
	if [ -z "\${AGENT_ID}" ]; then
		AGENT_ID="\$(command -v uuidgen >/dev/null 2>&1 && uuidgen | tr '[:upper:]' '[:lower:]')"
	fi
	if [ -z "\${AGENT_ID}" ] && command -v python3 >/dev/null 2>&1; then
		AGENT_ID="\$(python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || true)"
	fi
	if [ -z "\${AGENT_ID}" ]; then
		AGENT_ID="\$(date +%s)-\$(hostname)"
	fi
	cp /etc/edr/agent.yaml.default /etc/edr/agent.yaml
	sed -i "s#^  id: \"\"$\#  id: \"\${AGENT_ID}\"#" /etc/edr/agent.yaml || :
	chmod 0640 /etc/edr/agent.yaml
fi
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl daemon-reload || :
	systemctl enable edr-agent || :
	systemctl start edr-agent || :
fi

%preun
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl stop edr-agent 2>/dev/null || :
fi

%postun
if [ "\$1" -eq 0 ]; then
	if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
		systemctl disable edr-agent 2>/dev/null || :
		rm -f /etc/systemd/system/edr-agent.service
		systemctl daemon-reload 2>/dev/null || :
	fi
fi

%files
%attr(0755,root,root) /usr/local/bin/edr-agent
%attr(0755,root,root) /usr/local/bin/edrctl
%attr(0644,root,root) /etc/edr/agent.yaml.default
%attr(0644,root,root) /etc/systemd/system/edr-agent.service
/usr/share/edr
SPECEOF

rpmbuild --define "_topdir ${RPM_TOP}" -bb "${RPM_TOP}/SPECS/edr-agent.spec"
BUILT_RPM="$(find "${RPM_TOP}/RPMS" -name 'edr-agent-*.rpm' -type f | head -1)"
if [[ -z "${BUILT_RPM}" ]]; then
	echo "rpmbuild did not produce an .rpm" >&2
	exit 1
fi
cp -f "${BUILT_RPM}" "${RPM_OUT}"
echo "wrote ${RPM_OUT}"
