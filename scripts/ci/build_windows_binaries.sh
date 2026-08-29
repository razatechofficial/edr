#!/usr/bin/env bash
# Build Windows amd64 binaries for release/CI without GNU Make (windows-latest
# does not ship make; Chocolatey installs are brittle). Mirrors Makefile
# build-windows. When EDR_WINDOWS_YARA=1 (see setup_windows_yara.ps1), builds
# the agent with CGO + libyara for live YARA scanning.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || true)"
if [[ -z "${DATE}" ]]; then
	DATE="$(date -u "+%Y-%m-%dT%H:%M:%SZ")"
fi
BUILD_TIME="${DATE}"
LDFLAGS="-s -w \
	-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${DATE} \
	-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.Commit=${COMMIT}"

mkdir -p bin dist/windows-amd64

GOFLAGS="-trimpath"
if [[ "${EDR_WINDOWS_YARA:-0}" == "1" ]]; then
	export CGO_ENABLED=1
	if [[ -n "${EDR_GO_BUILD_TAGS:-}" ]]; then
		GOFLAGS="${GOFLAGS} -tags=${EDR_GO_BUILD_TAGS}"
	fi
	bash "${ROOT}/scripts/ci/patch_onnxruntime_getversion.sh"
	echo "==> Building Windows amd64 agent with YARA (CGO_ENABLED=1, tags=${EDR_GO_BUILD_TAGS:-none})"
else
	export CGO_ENABLED=0
	echo "==> Building Windows amd64 binaries (CGO_ENABLED=0, YARA stub)"
fi

GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o bin/edr-agent-windows-amd64.exe ./cmd/agent
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o bin/edrctl-windows-amd64.exe ./cmd/cli
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o bin/edr-installer-windows-amd64.exe ./cmd/installer
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o dist/windows-amd64/edr-agent.exe ./cmd/agent
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o dist/windows-amd64/edrctl.exe ./cmd/cli
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o dist/windows-amd64/edr-installer.exe ./cmd/installer
# Console does not scan; do not inherit agent YARA CGO flags or -tags.
CGO_ENABLED=1 CGO_CFLAGS= CGO_LDFLAGS= GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${LDFLAGS} -H windowsgui" -o dist/windows-amd64/edr-agent-ui.exe ./cmd/agentui
CGO_ENABLED=1 CGO_CFLAGS= CGO_LDFLAGS= GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${LDFLAGS} -H windowsgui" -o bin/edr-agent-ui-windows-amd64.exe ./cmd/agentui

# One-file attended setup: UI + privileged installer (agent + models + rules).
EMBED_INST="${ROOT}/bin/edr-installer-embedded.exe"
GOOS=windows GOARCH=amd64 LDFLAGS="${LDFLAGS}" \
	bash "${ROOT}/scripts/ci/stage_embedded_installer.sh" \
	"${ROOT}/dist/windows-amd64/edr-agent.exe" \
	"${ROOT}/dist/windows-amd64/edrctl.exe" \
	"${EMBED_INST}"
mkdir -p "${ROOT}/cmd/agentui/payload"
cp "${EMBED_INST}" "${ROOT}/cmd/agentui/payload/installer.bin"
CGO_ENABLED=1 CGO_CFLAGS= CGO_LDFLAGS= GOOS=windows GOARCH=amd64 go build -trimpath -tags embedsetup \
	-ldflags "${LDFLAGS} -H windowsgui" -o dist/windows-amd64/EDR-Agent-Setup.exe ./cmd/agentui
cp dist/windows-amd64/EDR-Agent-Setup.exe dist/EDR-Agent-Setup.exe
cp dist/windows-amd64/EDR-Agent-Setup.exe bin/EDR-Agent-Setup.exe

if [[ "${EDR_WINDOWS_YARA:-0}" == "1" ]]; then
	if command -v pwsh >/dev/null 2>&1; then
		pwsh -NoProfile -File "${ROOT}/scripts/ci/bundle_windows_yara.ps1" -Root "${ROOT}"
	elif command -v powershell >/dev/null 2>&1; then
		powershell -NoProfile -File "${ROOT}/scripts/ci/bundle_windows_yara.ps1" -Root "${ROOT}"
	fi
fi
