#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_DIR="${ROOT_DIR}/rules"
mkdir -p "${RULES_DIR}/sigma" "${RULES_DIR}/yara" "${RULES_DIR}/custom"

sync_repo() {
  local name="$1"
  local url="$2"
  local dst="$3"
  if [[ -d "${dst}/.git" ]]; then
    git -C "${dst}" pull --ff-only
  else
    rm -rf "${dst}"
    git clone --depth 1 "${url}" "${dst}"
  fi
  echo "synced ${name}"
}

sync_repo "sigmahq" "https://github.com/SigmaHQ/sigma.git" "${RULES_DIR}/sigma/upstream"
sync_repo "neo23x0-signature-base" "https://github.com/Neo23x0/signature-base.git" "${RULES_DIR}/yara/signature-base"
sync_repo "yara-rules" "https://github.com/Yara-Rules/rules.git" "${RULES_DIR}/yara/yara-rules"

echo "rule sync complete"
