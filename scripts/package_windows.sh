#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="${VERSION:-$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo "dev")}"
BIN_DIR="${BIN_DIR:-${ROOT_DIR}/bin}"
DIST_DIR="${ROOT_DIR}/dist"
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/edr-win-pkg.XXXXXX")"

cleanup() { rm -rf "${STAGING}"; }
trap cleanup EXIT

AGENT_SRC="${BIN_DIR}/edr-agent-windows-amd64.exe"
CTL_SRC="${BIN_DIR}/edrctl-windows-amd64.exe"

if [[ ! -f "${AGENT_SRC}" ]] || [[ ! -f "${CTL_SRC}" ]]; then
	echo "Missing Windows binaries. Build first: ${ROOT_DIR}/scripts/build.sh windows" >&2
	echo "Expected: ${AGENT_SRC} ${CTL_SRC}" >&2
	exit 1
fi

mkdir -p "${DIST_DIR}" "${STAGING}/config"
cp "${AGENT_SRC}" "${CTL_SRC}" "${STAGING}/"
cp "${SCRIPT_DIR}/windows/install.bat" "${SCRIPT_DIR}/windows/uninstall.bat" "${STAGING}/"

sed -e 's#data_dir: "/var/lib/edr"#data_dir: "C:/ProgramData/EDR/data"#g' \
	-e 's#temp_dir: "/tmp/edr"#temp_dir: "C:/ProgramData/EDR/temp"#g' \
	"${ROOT_DIR}/configs/agent.yaml" > "${STAGING}/config/agent.yaml"

OUT_ZIP="${DIST_DIR}/edr-agent-${VERSION}-windows-amd64.zip"
rm -f "${OUT_ZIP}"
( cd "${STAGING}" && zip -qr "${OUT_ZIP}" . )

echo "Wrote ${OUT_ZIP}"
