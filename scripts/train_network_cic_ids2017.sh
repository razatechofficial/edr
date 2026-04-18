#!/usr/bin/env bash
# Train network_anomaly.onnx on one CIC-IDS2017 MachineLearningCSV file.
# Prerequisites: valid MachineLearningCSV.zip extracted (see scripts/download-cic-ids2017.sh).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CIC_DIR="${ROOT}/ml/datasets/edr_datasets/cic-ids2017"
OUT="${ROOT}/models/network_cic_train_out"
MAX_SAMPLES="${MAX_SAMPLES:-200000}"
EPOCHS="${EPOCHS:-50}"

# Pick one CSV (Friday afternoon is a common choice; any labeled CIC file works)
CSV="${CIC_CSV:-}"
if [[ -z "$CSV" ]]; then
  CSV=$(find "$CIC_DIR" -name '*.csv' 2>/dev/null | head -n 1)
fi

if [[ -z "$CSV" || ! -f "$CSV" ]]; then
  echo "No .csv found under $CIC_DIR"
  echo "Extract MachineLearningCSV.zip there, then re-run."
  exit 1
fi

echo "Using CSV: $CSV"
cd "${ROOT}/ml/training"
export PYTHONPATH=.
# shellcheck disable=SC1091
source "${ROOT}/.venv/bin/activate"
python train_network_anomaly.py \
  --data-path "$CSV" \
  --dataset cic-ids2017 \
  --max-samples "$MAX_SAMPLES" \
  --output-dir "$OUT" \
  --epochs "$EPOCHS"

echo ""
echo "Artifacts: $OUT/network_anomaly.onnx , network_anomaly_threshold.npy"
echo "Copy to models/: cp $OUT/network_anomaly.onnx $OUT/network_anomaly_threshold.npy ${ROOT}/models/"
