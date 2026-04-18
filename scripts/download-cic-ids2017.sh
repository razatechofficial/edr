#!/usr/bin/env bash
# Download CIC-IDS2017 MachineLearningCSV.zip (network flow features for train_network_anomaly.py).
#
# Official UNB links often redirect to an HTML landing page; a naive curl saves ~106KB of HTML
# instead of the real ~200MB+ zip. This script validates the archive after download.
#
# Usage:
#   ./scripts/download-cic-ids2017.sh
# Or set KAGGLE_USERNAME / KAGGLE_KEY and use Kaggle (recommended if direct URL fails).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${ROOT}/ml/datasets/edr_datasets/cic-ids2017"
mkdir -p "$DEST"
cd "$DEST"

MIN_BYTES=$((50 * 1024 * 1024)) # 50 MiB — real zip is hundreds of MB

try_curl() {
  local url=$1
  echo "Trying: $url"
  if curl -fL --retry 3 --connect-timeout 30 -o MachineLearningCSV.zip.part "$url"; then
    mv MachineLearningCSV.zip.part MachineLearningCSV.zip
    return 0
  fi
  rm -f MachineLearningCSV.zip.part
  return 1
}

if [[ -f MachineLearningCSV.zip ]]; then
  sz=$(stat -f%z MachineLearningCSV.zip 2>/dev/null || stat -c%s MachineLearningCSV.zip)
  if [[ "$sz" -ge $MIN_BYTES ]] && unzip -t MachineLearningCSV.zip >/dev/null 2>&1; then
    echo "OK: existing MachineLearningCSV.zip looks valid (${sz} bytes)"
    exit 0
  fi
  echo "Removing invalid or tiny archive (${sz} bytes)"
  rm -f MachineLearningCSV.zip
fi

# Direct host (may redirect to HTML — curl -f should fail on non-200 in some cases; size check still required)
URLS=(
  "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip"
  "https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip"
)

ok=0
for u in "${URLS[@]}"; do
  if try_curl "$u"; then
    sz=$(stat -f%z MachineLearningCSV.zip 2>/dev/null || stat -c%s MachineLearningCSV.zip)
    if [[ "$sz" -ge $MIN_BYTES ]] && unzip -t MachineLearningCSV.zip >/dev/null 2>&1; then
      echo "Downloaded valid zip (${sz} bytes)"
      ok=1
      break
    fi
    echo "Invalid zip or HTML stub (${sz} bytes), removing."
    rm -f MachineLearningCSV.zip
  fi
done

if [[ "$ok" -ne 1 ]]; then
  cat <<'EOF'

Direct download did not yield a valid zip (UNB/CIC often redirect to HTML).

Options:
  1) Manual: open https://www.unb.ca/cic/datasets/ids-2017.html — use the official
     "MachineLearningCSV.zip" link, save to:
       ml/datasets/edr_datasets/cic-ids2017/MachineLearningCSV.zip

  2) Kaggle (requires ~/.kaggle/kaggle.json):
       pip install kaggle
       mkdir -p ml/datasets/edr_datasets/cic-ids2017 && cd "$_"
       kaggle datasets download -d cicdataset/cicids2017 -f MachineLearningCSV.zip
     (dataset slug may vary — search Kaggle for "CICIDS2017 MachineLearningCSV".)

  3) Then extract one CSV and train:
       unzip -o MachineLearningCSV.zip -d MachineLearningCSV
       cd /path/to/edr/ml/training && PYTHONPATH=. python train_network_anomaly.py \\
         --data-path .../Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \\
         --dataset cic-ids2017 --max-samples 200000 --output-dir .../models/network_cic_out

EOF
  exit 1
fi

unzip -o -q MachineLearningCSV.zip -d MachineLearningCSV || unzip -o -q MachineLearningCSV.zip
echo "Done. CSV files should be under: $DEST"
