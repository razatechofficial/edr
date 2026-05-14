#!/usr/bin/env bash
# Build Windows amd64 binaries for release/CI without GNU Make (windows-latest
# does not ship make; Chocolatey installs are brittle). Mirrors Makefile
# build-windows with CGO disabled (same as WINDOWS_CGO=0 on Windows hosts).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

# windows-latest ships with a C compiler on PATH, so CGO defaults to 1. That
# selects internal/detection/ml/onnx.go (cgo && windows) and onnxruntime_go,
# which fails in CI without ONNX headers/libs. Force pure Go like Makefile
# WINDOWS_CGO=0 dist build (see Makefile build-windows).
export CGO_ENABLED=0

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

echo "==> Building Windows amd64 binaries (CGO_ENABLED=${CGO_ENABLED})"
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o bin/edr-agent-windows-amd64.exe ./cmd/agent
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o bin/edrctl-windows-amd64.exe ./cmd/cli
GOOS=windows GOARCH=amd64 go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o dist/windows-amd64/edr-agent.exe ./cmd/agent
