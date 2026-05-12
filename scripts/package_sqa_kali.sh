#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

VERSION="${EDR_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}"
ARCH="${EDR_ARCH:-amd64}"
STAGE_NAME="edr-sqa-kali-${VERSION}-${ARCH}"
STAGE_DIR="${ROOT}/dist/${STAGE_NAME}"
AGENT_BIN="${ROOT}/dist/linux-${ARCH}/edr-agent"
EDRCTL_BIN="${ROOT}/bin/edrctl-linux-${ARCH}"
EBPF_OBJ="${ROOT}/platform/linux/ebpf/edr.bpf.o"
EBPF_VER="${ROOT}/internal/kernel/ebpf_expected_version.txt"
RULES_SRC="${ROOT}/rules"

require_file() {
	if [ ! -f "$1" ]; then
		echo "missing required file: $1" >&2
		exit 1
	fi
}

echo "==> Building Linux agent (CGO/YARA) and eBPF"
CGO_ENABLED=1 LINUX_CGO=1 EDR_VERSION="${VERSION}" make ebpf ebpf-link build-linux

require_file "${AGENT_BIN}"
require_file "${EBPF_OBJ}"
require_file "${EBPF_VER}"
require_file "${RULES_SRC}/baseline.yaml"

echo "==> Staging SQA bundle ${STAGE_NAME}"
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"/{bin,bpf,config,rules,systemd,sqa}

install -m 0755 "${AGENT_BIN}" "${STAGE_DIR}/bin/edr-agent"
install -m 0755 "${EDRCTL_BIN}" "${STAGE_DIR}/bin/edrctl"
install -m 0644 "${EBPF_OBJ}" "${STAGE_DIR}/bpf/edr.bpf.o"
install -m 0644 "${EBPF_VER}" "${STAGE_DIR}/bpf/edr.bpf.version"
cp -a "${RULES_SRC}/." "${STAGE_DIR}/rules/"
install -m 0644 "${ROOT}/configs/linux/config.yml" "${STAGE_DIR}/config/config.yml"
install -m 0644 "${ROOT}/configs/agent.example.yaml" "${STAGE_DIR}/config/agent.example.yaml"
install -m 0755 "${ROOT}/scripts/validate_on_device.sh" "${STAGE_DIR}/sqa/validate_on_device.sh"
install -m 0755 "${ROOT}/scripts/sqa_simulations.sh" "${STAGE_DIR}/sqa/sqa_simulations.sh"

cat > "${STAGE_DIR}/systemd/edr-agent.service" <<'UNIT'
[Unit]
Description=EDR Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/var/lib/edr-agent
ExecStart=/usr/local/bin/edr-agent --config /etc/edr-agent/agent.yaml --data-dir /var/lib/edr-agent
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_KILL
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_KILL
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
UNIT

cat > "${STAGE_DIR}/install.sh" <<'INSTALL'
#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
	echo "run as root: sudo ./install.sh" >&2
	exit 1
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p /usr/local/bin /etc/edr-agent /var/lib/edr-agent /var/lib/edr/bpf
install -m 0755 "${ROOT}/bin/edr-agent" /usr/local/bin/edr-agent
install -m 0755 "${ROOT}/bin/edrctl" /usr/local/bin/edrctl
install -m 0644 "${ROOT}/bpf/edr.bpf.o" /var/lib/edr/bpf/edr.bpf.o
install -m 0644 "${ROOT}/bpf/edr.bpf.version" /var/lib/edr/bpf/edr.bpf.version
rm -rf /etc/edr-agent/rules
mkdir -p /etc/edr-agent/rules
cp -a "${ROOT}/rules/." /etc/edr-agent/rules/
if [ ! -f /etc/edr-agent/agent.yaml ]; then
	install -m 0640 "${ROOT}/config/config.yml" /etc/edr-agent/agent.yaml
fi
install -m 0644 "${ROOT}/systemd/edr-agent.service" /etc/systemd/system/edr-agent.service
systemctl daemon-reload
systemctl enable edr-agent
systemctl restart edr-agent
echo "installed; check: systemctl status edr-agent --no-pager"
INSTALL
chmod 0755 "${STAGE_DIR}/install.sh"

cat > "${STAGE_DIR}/SQA_INSTALL.txt" <<'TXT'
EDR SQA package for Kali Linux / Debian amd64

Prerequisites on the target host:
  sudo apt update
  sudo apt install -y libyara-dev libyara10 systemd

Install:
  tar xzf edr-sqa-kali-*.tar.gz
  cd edr-sqa-kali-*
  sudo ./install.sh

Built-in validation:
  sudo ./sqa/validate_on_device.sh ./bin/edr-agent ./config/agent.example.yaml

Production-style validation:
  sudo systemctl status edr-agent --no-pager
  sudo ./sqa/sqa_simulations.sh

Test-mode validation:
  sudo ./bin/edr-agent --config ./config/agent.example.yaml --data-dir /var/lib/edr-agent --test-mode

Artifacts to collect:
  /var/lib/edr-agent/validation_report.json
  /var/lib/edr-agent/monitoring_report.json
  /var/lib/edr-agent/monitoring_health.json
  /var/lib/edr-agent/alerts.jsonl
TXT

TARBALL="${ROOT}/dist/${STAGE_NAME}.tar.gz"
tar -C "${ROOT}/dist" -czf "${TARBALL}" "${STAGE_NAME}"
echo "==> Wrote ${TARBALL}"

if command -v dpkg-deb >/dev/null 2>&1; then
	echo "==> Building .deb via build/linux/package.sh"
	EDR_VERSION="${VERSION}" EDR_ARCH="${ARCH}" bash "${ROOT}/build/linux/package.sh" "${VERSION}" "${ARCH}"
else
	echo "==> dpkg-deb not found; skipped .deb (tarball is ready)"
fi

ls -lh "${TARBALL}" 2>/dev/null || true
ls -lh "${ROOT}/dist/"edr-agent_*.deb 2>/dev/null || true
