#!/usr/bin/env bash
set -euo pipefail

DEB_PATH="${1:-}"
if [ -z "${DEB_PATH}" ]; then
  echo "usage: $0 dist/edr-agent_<version>_amd64.deb" >&2
  exit 1
fi
if [ ! -f "${DEB_PATH}" ]; then
  echo "package not found: ${DEB_PATH}" >&2
  exit 1
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb required for package verification" >&2
  exit 1
fi

echo "Verifying package metadata: ${DEB_PATH}"
PKG_INFO="$(dpkg-deb -f "${DEB_PATH}")"
VERSION="$(printf "%s\n" "${PKG_INFO}" | awk '/^Version:/{print $2}')"
if ! [[ "${VERSION}" =~ ^[0-9] ]]; then
  echo "invalid Debian version in package: ${VERSION}" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
dpkg-deb -x "${DEB_PATH}" "${tmpdir}"

required_paths=(
  "usr/bin/edr-agent"
  "etc/edr-agent/config.yml"
  "etc/edr-agent/rules/baseline.yaml"
  "etc/edr-agent/rules/playbooks/playbooks.yml"
  "var/lib/edr/bpf/edr.bpf.o"
)
for p in "${required_paths[@]}"; do
  if [ ! -e "${tmpdir}/${p}" ]; then
    echo "missing required packaged path: ${p}" >&2
    exit 1
  fi
done

cfg="${tmpdir}/etc/edr-agent/config.yml"
grep -q '^rules_file: /etc/edr-agent/rules/baseline.yaml$' "${cfg}" || { echo "rules_file must be absolute in config.yml" >&2; exit 1; }
grep -q '^  playbooks_path: /etc/edr-agent/rules/playbooks/playbooks.yml$' "${cfg}" || { echo "playbooks_path must be absolute in config.yml" >&2; exit 1; }
grep -q '^    rules_dir: /etc/edr-agent/rules/sigma$' "${cfg}" || { echo "sigma rules_dir must be absolute in config.yml" >&2; exit 1; }
grep -q '^    rules_dir: /etc/edr-agent/rules/yara$' "${cfg}" || { echo "yara rules_dir must be absolute in config.yml" >&2; exit 1; }

"${tmpdir}/usr/bin/edr-agent" --version >/dev/null

echo "Package verification passed"
