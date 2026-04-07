#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODELS_DIR="${ROOT_DIR}/models"
mkdir -p "${MODELS_DIR}"

download() {
  local url="$1"
  local out="$2"
  if [[ -z "${url}" ]]; then
    echo "skip ${out}: URL not configured"
    return 0
  fi
  echo "downloading ${out}"
  curl -fsSL "${url}" -o "${MODELS_DIR}/${out}"
}

download "${MODEL_SRC_PE:-}" "pe_classifier.onnx"
download "${MODEL_SRC_BEHAVIOR:-}" "behavior_lstm.onnx"
download "${MODEL_SRC_NETWORK:-}" "network_anomaly.onnx"
download "${MODEL_SRC_RANSOMWARE:-}" "ransomware.onnx"

echo "model download workflow complete"
