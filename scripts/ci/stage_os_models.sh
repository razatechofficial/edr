#!/usr/bin/env bash
# Stage OS-specific ONNX models for a package build (smaller, faster installs).
# Usage: stage_os_models.sh <os> <dest_dir>
#   os = windows|darwin|linux
set -euo pipefail
OS="${1:?os required}"
DEST="${2:?dest dir required}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="${ROOT}/models"
mkdir -p "${DEST}"

# Core models only — omit aigen_detector (~61MB) and other optional packs.
COMMON=(
  behavior_lstm.onnx
  network_anomaly.onnx
  ransomware.onnx
  network_lgbm.onnx
  rat_c2_detector.onnx
)
WINDOWS_ONLY=(pe_classifier.onnx)

copy_one() {
  local f="$1"
  if [[ -f "${SRC}/${f}" ]]; then
    cp "${SRC}/${f}" "${DEST}/${f}"
    [[ -f "${SRC}/${f}.sig" ]] && cp "${SRC}/${f}.sig" "${DEST}/${f}.sig"
  else
    echo "warning: missing model ${f}" >&2
  fi
}

for f in "${COMMON[@]}"; do
  copy_one "${f}"
done
case "${OS}" in
  windows)
    for f in "${WINDOWS_ONLY[@]}"; do copy_one "${f}"; done
    ;;
  darwin|linux) ;;
  *)
    echo "unknown os: ${OS}" >&2
    exit 1
    ;;
esac
if [[ -f "${SRC}/manifest.json" ]]; then
  cp "${SRC}/manifest.json" "${DEST}/manifest.json"
fi
echo "Staged $(ls -1 "${DEST}"/*.onnx 2>/dev/null | wc -l | tr -d ' ') models for ${OS} -> ${DEST}"
