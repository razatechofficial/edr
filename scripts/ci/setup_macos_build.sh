#!/usr/bin/env bash
set -euo pipefail

if ! command -v brew >/dev/null 2>&1; then
	echo "Homebrew is required on macOS build runners" >&2
	exit 1
fi

brew update
brew install yara pkg-config

if [ -n "${GITHUB_ENV:-}" ]; then
	{
		echo "CGO_ENABLED=1"
		echo "PKG_CONFIG_PATH=$(brew --prefix yara)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
	} >>"${GITHUB_ENV}"
fi

export CGO_ENABLED=1
export PKG_CONFIG_PATH="$(brew --prefix yara)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
