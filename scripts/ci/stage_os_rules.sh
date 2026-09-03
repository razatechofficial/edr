#!/usr/bin/env bash
# Stage OS-local rules only (skip other OS trees) for faster packages.
# Usage: stage_os_rules.sh <os> <dest_dir>
set -euo pipefail
OS="${1:?os required}"
DEST="${2:?dest dir required}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="${ROOT}/rules"
mkdir -p "${DEST}"

rsync -a --delete \
  --exclude '.git/' \
  --exclude 'yara/windows/' \
  --exclude 'yara/macos/' \
  --exclude 'yara/linux/' \
  --exclude 'compliance/sca/windows/' \
  --exclude 'compliance/sca/darwin/' \
  --exclude 'compliance/sca/linux/' \
  "${SRC}/" "${DEST}/"

case "${OS}" in
  windows)
    [[ -d "${SRC}/yara/windows" ]] && rsync -a "${SRC}/yara/windows/" "${DEST}/yara/windows/"
    [[ -d "${SRC}/compliance/sca/windows" ]] && rsync -a "${SRC}/compliance/sca/windows/" "${DEST}/compliance/sca/windows/"
    ;;
  darwin)
    [[ -d "${SRC}/yara/macos" ]] && rsync -a "${SRC}/yara/macos/" "${DEST}/yara/macos/"
    [[ -d "${SRC}/compliance/sca/darwin" ]] && rsync -a "${SRC}/compliance/sca/darwin/" "${DEST}/compliance/sca/darwin/"
    ;;
  linux)
    [[ -d "${SRC}/yara/linux" ]] && rsync -a "${SRC}/yara/linux/" "${DEST}/yara/linux/"
    [[ -d "${SRC}/compliance/sca/linux" ]] && rsync -a "${SRC}/compliance/sca/linux/" "${DEST}/compliance/sca/linux/"
    ;;
  *)
    echo "unknown os: ${OS}" >&2
    exit 1
    ;;
esac
echo "Staged OS-local rules for ${OS} -> ${DEST}"
