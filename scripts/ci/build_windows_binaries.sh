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

# Service + installer are WINDOWS subsystem so msiexec / --install never flash a console.
WINSVC_LDFLAGS="${LDFLAGS} -H windowsgui"
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${WINSVC_LDFLAGS}" -o bin/edr-agent-windows-amd64.exe ./cmd/agent
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o bin/edrctl-windows-amd64.exe ./cmd/cli
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${WINSVC_LDFLAGS}" -o bin/edr-installer-windows-amd64.exe ./cmd/installer
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${WINSVC_LDFLAGS}" -o dist/windows-amd64/edr-agent.exe ./cmd/agent
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o dist/windows-amd64/edrctl.exe ./cmd/cli
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${WINSVC_LDFLAGS}" -o dist/windows-amd64/edr-installer.exe ./cmd/installer
# CGO-free service registrar for MSI (must not link libyara / MinGW runtime).
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${LDFLAGS}" -o dist/windows-amd64/edr-svcreg.exe ./cmd/svcreg
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${LDFLAGS}" -o bin/edr-svcreg-windows-amd64.exe ./cmd/svcreg
# Win32 operator window (no OpenGL). Start Menu on Server/RDP uses this.
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${WINSVC_LDFLAGS}" -o dist/windows-amd64/edr-console.exe ./cmd/winconsole
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${WINSVC_LDFLAGS}" -o bin/edr-console-windows-amd64.exe ./cmd/winconsole
# Console does not scan; do not inherit agent YARA CGO flags or -tags.
# Do not build EDR-Agent-Setup.exe (embedsetup) — that lives on attended-setup.
CGO_ENABLED=1 CGO_CFLAGS= CGO_LDFLAGS= GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${LDFLAGS} -H windowsgui" -o dist/windows-amd64/edr-agent-ui.exe ./cmd/agentui
CGO_ENABLED=1 CGO_CFLAGS= CGO_LDFLAGS= GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${LDFLAGS} -H windowsgui" -o bin/edr-agent-ui-windows-amd64.exe ./cmd/agentui

# Software OpenGL for Windows Server / Hyper-V / RDP (Fyne requires WGL).
# Required for release MSIs — do not ship a console that exits with no window.
if command -v pwsh >/dev/null 2>&1; then
	pwsh -NoProfile -File "${ROOT}/scripts/ci/bundle_windows_mesa.ps1" -Root "${ROOT}" -Required
elif command -v powershell >/dev/null 2>&1; then
	powershell -NoProfile -File "${ROOT}/scripts/ci/bundle_windows_mesa.ps1" -Root "${ROOT}" -Required
else
	echo "ERROR: pwsh/powershell required to bundle Mesa opengl32.dll" >&2
	exit 1
fi
if [[ ! -f "${ROOT}/dist/windows-amd64/opengl32.dll" ]]; then
	echo "ERROR: Mesa opengl32.dll missing after bundle (Server/RDP UI will not open)" >&2
	exit 1
fi

if [[ "${EDR_WINDOWS_YARA:-0}" == "1" ]]; then
	if command -v pwsh >/dev/null 2>&1; then
		pwsh -NoProfile -File "${ROOT}/scripts/ci/bundle_windows_yara.ps1" -Root "${ROOT}"
	elif command -v powershell >/dev/null 2>&1; then
		powershell -NoProfile -File "${ROOT}/scripts/ci/bundle_windows_yara.ps1" -Root "${ROOT}"
	fi
fi
