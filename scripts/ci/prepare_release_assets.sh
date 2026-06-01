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
if compgen -G "${ROOT}/models/*.onnx" >/dev/null; then
	echo "Using existing ONNX models in models/"
elif [[ -n "${MODEL_SRC_PE:-}${MODEL_SRC_BEHAVIOR:-}${MODEL_SRC_NETWORK:-}${MODEL_SRC_RANSOMWARE:-}" ]]; then
	if make models-update; then
		echo "Downloaded production models"
	else
		echo "WARNING: model download failed; generating synthetic baseline" >&2
		make models-bootstrap
	fi
else
	echo "No MODEL_SRC_* URLs; generating synthetic baseline ONNX"
	make models-bootstrap
fi

if compgen -G "${ROOT}/models/*.onnx" >/dev/null; then
	make models-validate || echo "WARNING: models-validate failed (non-fatal)" >&2
else
	echo "WARNING: no ONNX models available after bootstrap" >&2
	exit 1
fi

echo "Release assets ready (rules/ioc + models/*.onnx)"
