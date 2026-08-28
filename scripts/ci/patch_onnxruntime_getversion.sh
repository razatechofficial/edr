#!/usr/bin/env bash
# Rename onnxruntime_go's C GetVersion() to avoid Win32 GetVersion symbol clash
# when linking with MinGW + libyara/openssl (kernel32).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

# go list -m only returns .Dir after the module is in the cache. CI logs showed
# this script skipping, then go build downloading onnxruntime_go unpatched.
echo "==> Downloading github.com/yalue/onnxruntime_go for GetVersion patch"
go mod download github.com/yalue/onnxruntime_go

MOD_DIR="$(go list -f '{{.Dir}}' -m github.com/yalue/onnxruntime_go)"
if command -v cygpath >/dev/null 2>&1 && [[ -n "${MOD_DIR}" ]]; then
	MOD_DIR="$(cygpath -u "${MOD_DIR}")"
fi
MOD_DIR="${MOD_DIR//\\//}"

if [[ -z "${MOD_DIR}" || ! -d "${MOD_DIR}" ]]; then
	echo "patch_onnxruntime_getversion: onnxruntime_go module not found (${MOD_DIR:-empty})" >&2
	exit 1
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
chmod u+w "${WRAPPER_C}" "${WRAPPER_H}" "${WRAPPER_GO}"

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
