#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-dev}"
ARCH="${2:-amd64}"
TARGET_OS="${3:-$(uname | tr '[:upper:]' '[:lower:]')}"

case "${TARGET_OS}" in
  linux)
    bash build/linux/package.sh "${VERSION}" "${ARCH}"
    ;;
  darwin|macos)
    bash build/macos/package.sh "${VERSION}" "${ARCH}"
    ;;
  windows)
    cmd.exe /c build\\windows\\build_msi.bat "${VERSION}"
    ;;
  *)
    echo "unsupported target os: ${TARGET_OS}" >&2
    exit 1
    ;;
esac
