#!/usr/bin/env bash
set -euo pipefail

# Build EDR agent for all platforms.
#
# Usage:
#   ./scripts/build.sh                  Build for all platforms
#   ./scripts/build.sh linux            Build Linux only
#   ./scripts/build.sh darwin           Build macOS only
#   ./scripts/build.sh windows          Build Windows only
#   ./scripts/build.sh current          Build for current OS/arch
#
# Environment:
#   VERSION   Override version string (default: git describe)
#   BIN_DIR   Override output directory (default: bin/)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
BIN_DIR="${BIN_DIR:-bin}"

GOFLAGS="-trimpath"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"

mkdir -p "${BIN_DIR}"

build_binary() {
    local goos="$1"
    local goarch="$2"
    local pkg="$3"
    local name="$4"

    local ext=""
    if [ "${goos}" = "windows" ]; then
        ext=".exe"
    fi

    local output="${BIN_DIR}/${name}-${goos}-${goarch}${ext}"
    echo "  Building ${output}"
    GOOS="${goos}" GOARCH="${goarch}" go build ${GOFLAGS} -ldflags "${LDFLAGS}" -o "${output}" "${pkg}"
}

build_linux() {
    echo "==> Building Linux amd64"
    build_binary linux amd64 ./cmd/agent      edr-agent
    build_binary linux amd64 ./cmd/installer  edr-installer
    build_binary linux amd64 ./cmd/cli        edrctl
}

build_darwin() {
    echo "==> Building macOS amd64"
    build_binary darwin amd64 ./cmd/agent edr-agent
    build_binary darwin amd64 ./cmd/cli   edrctl

    echo "==> Building macOS arm64"
    build_binary darwin arm64 ./cmd/agent edr-agent
    build_binary darwin arm64 ./cmd/cli   edrctl
}

build_windows() {
    echo "==> Building Windows amd64"
    build_binary windows amd64 ./cmd/agent     edr-agent
    build_binary windows amd64 ./cmd/installer edr-installer
    build_binary windows amd64 ./cmd/cli       edrctl
}

build_current() {
    local goos
    local goarch
    goos="$(go env GOOS)"
    goarch="$(go env GOARCH)"

    echo "==> Building for ${goos}/${goarch}"
    build_binary "${goos}" "${goarch}" ./cmd/agent     edr-agent
    build_binary "${goos}" "${goarch}" ./cmd/installer edr-installer
    build_binary "${goos}" "${goarch}" ./cmd/cli       edrctl
}

TARGET="${1:-all}"

case "${TARGET}" in
    linux)
        build_linux
        ;;
    darwin)
        build_darwin
        ;;
    windows)
        build_windows
        ;;
    current)
        build_current
        ;;
    all)
        build_linux
        build_darwin
        build_windows
        ;;
    *)
        echo "Unknown target: ${TARGET}"
        echo "Usage: $0 [linux|darwin|windows|current|all]"
        exit 1
        ;;
esac

echo ""
echo "==> Build complete (version=${VERSION} commit=${COMMIT})"
ls -lh "${BIN_DIR}/"
