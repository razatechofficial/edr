#!/usr/bin/env bash
# Rename onnxruntime_go's C GetVersion() to avoid Win32 GetVersion symbol clash
# when linking with MinGW + libyara/openssl (kernel32).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

MOD_DIR="$(go list -f '{{.Dir}}' -m github.com/yalue/onnxruntime_go 2>/dev/null || true)"
if [[ -z "${MOD_DIR}" || ! -d "${MOD_DIR}" ]]; then
	echo "patch_onnxruntime_getversion: onnxruntime_go module not found, skipping"
	exit 0
fi

WRAPPER_C="${MOD_DIR}/onnxruntime_wrapper.c"
WRAPPER_H="${MOD_DIR}/onnxruntime_wrapper.h"
WRAPPER_GO="${MOD_DIR}/onnxruntime_go.go"

for f in "${WRAPPER_C}" "${WRAPPER_H}" "${WRAPPER_GO}"; do
	if [[ ! -f "${f}" ]]; then
		echo "patch_onnxruntime_getversion: missing ${f}" >&2
		exit 1
	fi
done

if grep -q 'OrtWrapperGetVersion' "${WRAPPER_C}"; then
	echo "patch_onnxruntime_getversion: already patched"
	exit 0
fi

echo "==> Patching onnxruntime_go GetVersion symbol for Windows MinGW link (${MOD_DIR})"

sed_inplace() {
	local file=$1
	shift
	if sed --version 2>/dev/null | grep -q GNU; then
		sed -i "$@" "${file}"
	else
		sed -i '' "$@" "${file}"
	fi
}

# Wrapper export only — do not touch ModelMetadataGetVersion / GetVersionString.
sed_inplace "${WRAPPER_H}" 's/const char \*GetVersion();/const char *OrtWrapperGetVersion();/'
sed_inplace "${WRAPPER_C}" 's/const char \*GetVersion()/const char *OrtWrapperGetVersion()/'
sed_inplace "${WRAPPER_GO}" 's/C\.GetVersion()/C.OrtWrapperGetVersion()/'

if ! grep -q 'OrtWrapperGetVersion' "${WRAPPER_C}"; then
	echo "patch_onnxruntime_getversion: patch failed" >&2
	exit 1
fi

echo "patch_onnxruntime_getversion: OK"
