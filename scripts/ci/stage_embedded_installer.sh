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

want_lipo=""
case "${GOARCH:-$(go env GOARCH)}" in
amd64) want_lipo=x86_64 ;;
arm64 | aarch64) want_lipo=arm64 ;;
esac
if [[ -n "${want_lipo}" ]] && command -v lipo >/dev/null 2>&1; then
	got_lipo="$(lipo -archs "${AGENT}" 2>/dev/null || true)"
	if ! grep -qw "${want_lipo}" <<<"${got_lipo}"; then
		echo "error: ${AGENT} is ${got_lipo:-unknown}, need ${want_lipo} (GOARCH=${GOARCH:-})" >&2
		exit 1
	fi
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
# setup_macos_build.sh exports CGO_* with Homebrew libyara for the sensor.
# The installer only needs Security.framework (Keychain). Inheriting -lyara
# makes Hardened Runtime reject EDR Agent.app and fails verify_macos_pkg.sh.
export CGO_CFLAGS=
export CGO_CPPFLAGS=
export CGO_LDFLAGS=
target_os="${GOOS:-$(go env GOOS)}"
if [[ "${target_os}" == "darwin" ]]; then
	export CGO_ENABLED=1
fi
GOOS="${target_os}" GOARCH="${GOARCH:-$(go env GOARCH)}" \
	go build -trimpath -tags embedbundle -ldflags "${LDFLAGS:-}" \
	-o "${OUT}" ./cmd/installer

if [[ "${target_os}" == "darwin" ]] && command -v otool >/dev/null 2>&1; then
	if otool -L "${OUT}" | grep -Eiq '/opt/yara/|/Cellar/yara/|/usr/local/opt/yara/'; then
		echo "error: ${OUT} linked Homebrew libyara; CGO flags leaked into the installer" >&2
		otool -L "${OUT}" >&2 || true
		exit 1
	fi
fi

echo "embedded installer: ${OUT}"
