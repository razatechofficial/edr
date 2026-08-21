#!/usr/bin/env bash
# Refresh IOC feeds and ensure ONNX models exist before release packaging.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

echo "==> Refresh IOC threat intel"
if make intel-update; then
	echo "IOC refresh complete"
else
	echo "WARNING: intel-update failed; merging baseline IOC files only" >&2
	bash scripts/convert-intel.sh || true
fi

echo "==> Prepare ML models for packaging"
# Prefer the 12 checked-in ONNX files. Do not pip-install torch unless none exist.
bash "${ROOT}/scripts/ci/ensure_onnx_models.sh"
if compgen -G "${ROOT}/models/*.onnx" >/dev/null; then
	make models-validate || echo "WARNING: models-validate failed (non-fatal)" >&2
else
	echo "WARNING: no ONNX models available after ensure" >&2
	exit 1
fi

echo "Release assets ready (rules/ioc + models/*.onnx)"
