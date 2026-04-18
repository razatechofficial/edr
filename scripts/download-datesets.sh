#!/bin/bash
set -e
BASE="/Volumes/Data/common/sync/Go-lang/prod/edr/ml/datasets"
mkdir -p "$BASE"

echo "=== 1/5 EMBER 2018 (PE malware, ~4GB) ==="
cd "$BASE"
curl -L -O https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar xjf ember_dataset_2018_2.tar.bz2

echo "=== 2/5 CIC-IDS2017 (network flows, ~200MB+ zip) ==="
# NOTE: Plain curl to the old UNB URL often saves an HTML redirect (~106KB), not a zip.
# Use:  bash scripts/download-cic-ids2017.sh
# Or download MachineLearningCSV.zip manually from https://www.unb.ca/cic/datasets/ids-2017.html
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -x "$SCRIPT_DIR/download-cic-ids2017.sh" ]]; then
  bash "$SCRIPT_DIR/download-cic-ids2017.sh"
else
  echo "Run: bash scripts/download-cic-ids2017.sh"
fi

echo "=== 3/5 UNSW-NB15 (network anomaly, ~600MB) ==="
mkdir -p "$BASE/unsw-nb15" && cd "$BASE/unsw-nb15"
# Using HuggingFace - no auth required
cd /Volumes/Data/common/sync/Go-lang/prod/edr
.venv/bin/pip install datasets
.venv/bin/python3 -c "
from datasets import load_dataset
ds = load_dataset('Mouwiya/UNSW-NB15')
ds['train'].to_csv('ml/datasets/unsw-nb15/train.csv')
ds['test'].to_csv('ml/datasets/unsw-nb15/test.csv')
"

echo "=== 4/5 BETH (host behavior, ~1.5GB) ==="
mkdir -p "$BASE/beth" && cd "$BASE/beth"
kaggle datasets download -d katehighnam/beth-dataset
unzip beth-dataset.zip

echo "=== 5/5 CIC-MalMem-2022 (ransomware memory, ~200MB) ==="
mkdir -p "$BASE/cic-malmem" && cd "$BASE/cic-malmem"
kaggle datasets download -d hasanccr92/cic-malmem-2022
unzip cic-malmem-2022.zip

echo "=== All datasets downloaded ==="
ls -lhR "$BASE"