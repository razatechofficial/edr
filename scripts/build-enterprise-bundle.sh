#!/usr/bin/env bash
# Build a single-folder enterprise distribution: edr-installer + edr-agent + edrctl + models/ + rules/
# Run the installer from this folder (no manual YAML editing):
#   cd dist/edr-enterprise-macos && sudo ./edr-installer install
#
# Requires: make build (or build-darwin) so bin/ contains binaries for current OS.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${OUT:-${ROOT}/dist/edr-enterprise-macos}"

if [[ ! -d "${ROOT}/models" ]] || ! ls "${ROOT}"/models/*.onnx >/dev/null 2>&1; then
	echo "error: ${ROOT}/models must contain at least one .onnx file" >&2
	exit 1
fi
if [[ ! -d "${ROOT}/rules" ]]; then
	echo "error: ${ROOT}/rules not found" >&2
	exit 1
fi

if [[ ! -f "${ROOT}/bin/edr-installer" ]]; then
	echo "error: run 'make build' first (need bin/edr-installer)" >&2
	exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"

cp "${ROOT}/bin/edr-installer" "$OUT/"
cp "${ROOT}/bin/edr-agent" "$OUT/" 2>/dev/null || true
cp "${ROOT}/bin/edrctl" "$OUT/" 2>/dev/null || true

rsync -a "${ROOT}/models/" "${OUT}/models/"
rsync -a "${ROOT}/rules/" "${OUT}/rules/"

echo ""
echo "Enterprise bundle ready:"
echo "  $OUT"
echo ""
echo "Install on this Mac (no config edits):"
echo "  cd \"$OUT\" && sudo ./edr-installer install"
echo ""
echo "Single-file installer (embeds agent + models + rules in one binary):"
echo "  make build-installer-embedded"
echo "  sudo ./bin/edr-installer-embedded install"
echo ""
