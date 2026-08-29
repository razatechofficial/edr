#!/usr/bin/env bash
# Stage models + rules + agent (+ optional edrctl) into cmd/installer/bundle
# and build a single edr-installer with -tags embedbundle.
#
# Usage:
#   stage_embedded_installer.sh <agent-bin> [edrctl-bin] [out-installer]
#
# Honors GOOS / GOARCH / LDFLAGS from the environment (Windows CI sets GOOS=windows).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

AGENT="${1:-}"
CTL="${2:-}"
OUT="${3:-}"

if [[ -z "${AGENT}" || ! -f "${AGENT}" ]]; then
	echo "usage: $0 path/to/edr-agent [path/to/edrctl] [out-installer]" >&2
	exit 1
fi

if [[ -z "${OUT}" ]]; then
	if [[ "${GOOS:-$(go env GOOS)}" == "windows" ]]; then
		OUT="${ROOT}/bin/edr-installer-embedded.exe"
	else
		OUT="${ROOT}/bin/edr-installer-embedded"
	fi
fi

bash "${ROOT}/scripts/ci/ensure_onnx_models.sh"

if [[ ! -d "${ROOT}/models" ]] || ! ls "${ROOT}/models"/*.onnx >/dev/null 2>&1; then
	echo "error: models/ must contain at least one .onnx" >&2
	exit 1
fi
if [[ ! -d "${ROOT}/rules" ]]; then
	echo "error: rules/ missing" >&2
	exit 1
fi

mkdir -p "${ROOT}/cmd/installer/bundle/bin" \
	"${ROOT}/cmd/installer/bundle/models" \
	"${ROOT}/cmd/installer/bundle/rules"

copy_tree() {
	local src="$1"
	local dst="$2"
	rm -rf "${dst}"
	mkdir -p "${dst}"
	if command -v rsync >/dev/null 2>&1; then
		rsync -a "${src}/" "${dst}/"
	else
		cp -R "${src}/." "${dst}/"
	fi
}
copy_tree "${ROOT}/models" "${ROOT}/cmd/installer/bundle/models"
copy_tree "${ROOT}/rules" "${ROOT}/cmd/installer/bundle/rules"

agent_name="edr-agent"
ctl_name="edrctl"
if [[ "${GOOS:-$(go env GOOS)}" == "windows" ]]; then
	agent_name="edr-agent.exe"
	ctl_name="edrctl.exe"
fi
cp "${AGENT}" "${ROOT}/cmd/installer/bundle/bin/${agent_name}"
if [[ -n "${CTL}" && -f "${CTL}" ]]; then
	cp "${CTL}" "${ROOT}/cmd/installer/bundle/bin/${ctl_name}"
fi

mkdir -p "$(dirname "${OUT}")"
GOOS="${GOOS:-$(go env GOOS)}" GOARCH="${GOARCH:-$(go env GOARCH)}" \
	go build -trimpath -tags embedbundle -ldflags "${LDFLAGS:-}" \
	-o "${OUT}" ./cmd/installer

echo "embedded installer: ${OUT}"
