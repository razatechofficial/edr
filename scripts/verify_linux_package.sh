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
  "etc/edr-agent/config.tenant.yml"
  "etc/edr-agent/config.tenant.tls.yml"
  "etc/edr-agent/config.fleet.tls.yml"
  "etc/edr-agent/rules/baseline.yaml"
  "etc/edr-agent/rules/playbooks/playbooks.yml"
  "etc/edr-agent/rules/yara/exploits/cve_2021_44228_log4j.yar"
  "var/lib/edr/bpf/edr.bpf.o"
  "var/lib/edr/bpf/edr.bpf.version"
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
if ! awk '
  $0 == "ml:" { in_ml=1; next }
  in_ml && /^[^ ]/ { in_ml=0 }
  in_ml && $0 ~ /^  enabled: true$/ { found=1 }
  END { exit found ? 0 : 1 }
' "${cfg}"; then
  echo "config.yml must set ml.enabled: true" >&2
  exit 1
fi
grep -q '^  models_dir: /usr/share/edr-agent/models$' "${cfg}" || {
  echo "config.yml must set ml.models_dir to /usr/share/edr-agent/models" >&2
  exit 1
}

# Lean OS package: core models only (no aigen ~61MB; no Windows PE on Linux).
models_dir="${tmpdir}/usr/share/edr-agent/models"
required_models=(
  behavior_lstm.onnx
  network_anomaly.onnx
  ransomware.onnx
  network_lgbm.onnx
  rat_c2_detector.onnx
)
for m in "${required_models[@]}"; do
  if [ ! -f "${models_dir}/${m}" ]; then
    echo "missing required ONNX model: ${m}" >&2
    exit 1
  fi
done
if [ -f "${models_dir}/aigen_detector.onnx" ]; then
  echo "aigen_detector.onnx must not ship in the default Linux package" >&2
  exit 1
fi
if [ -f "${models_dir}/pe_classifier.onnx" ]; then
  echo "pe_classifier.onnx is Windows-only and must not ship in the Linux package" >&2
  exit 1
fi
onnx_count="$(find "${models_dir}" -name '*.onnx' 2>/dev/null | wc -l | tr -d ' ')"
if [ "${onnx_count}" -lt "${#required_models[@]}" ]; then
  echo "expected at least ${#required_models[@]} ONNX models in package, found ${onnx_count}" >&2
  exit 1
fi

"${tmpdir}/usr/bin/edr-agent" --version >/dev/null

echo "Package verification passed"
