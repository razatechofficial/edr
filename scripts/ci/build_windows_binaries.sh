#!/usr/bin/env bash
# Build Windows amd64 binaries for release/CI without GNU Make (windows-latest
# does not ship make; Chocolatey installs are brittle). Mirrors Makefile
# build-windows with CGO disabled (same as WINDOWS_CGO=0 on Windows hosts).
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
GOFLAGS="-trimpath"
LDFLAGS="-s -w \
	-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${DATE} \
	-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.Commit=${COMMIT}"

mkdir -p bin dist/windows-amd64

echo "==> Building Windows amd64 binaries (CGO=0)"
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o bin/edr-agent-windows-amd64.exe ./cmd/agent
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o bin/edrctl-windows-amd64.exe ./cmd/cli
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o dist/windows-amd64/edr-agent.exe ./cmd/agent
