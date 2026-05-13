#!/usr/bin/env bash
set -euo pipefail

if ! command -v brew >/dev/null 2>&1; then
	echo "Homebrew is required on macOS build runners" >&2
	exit 1
fi

export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_INSTALL_CLEANUP=1

if ! brew list yara >/dev/null 2>&1; then
	brew install yara
fi
if ! brew list pkg-config >/dev/null 2>&1; then
	brew install pkg-config
fi
if ! brew list openssl@3 >/dev/null 2>&1; then
	brew install openssl@3
fi

yara_prefix="$(brew --prefix yara)"
openssl_prefix="$(brew --prefix openssl@3)"
export PKG_CONFIG_PATH="${yara_prefix}/lib/pkgconfig:${openssl_prefix}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export CGO_ENABLED=1
export CGO_CPPFLAGS="${CGO_CPPFLAGS:-} -I${openssl_prefix}/include"
export CGO_CFLAGS="${CGO_CFLAGS:-} $(pkg-config --cflags yara 2>/dev/null || true)"
export CGO_LDFLAGS="${CGO_LDFLAGS:-} $(pkg-config --libs yara 2>/dev/null || true) -L${openssl_prefix}/lib"

if ! pkg-config --exists yara; then
	echo "ERROR: yara pkg-config metadata not found after brew install" >&2
	exit 1
fi

if [ -n "${GITHUB_ENV:-}" ]; then
	{
		echo "CGO_ENABLED=1"
		echo "PKG_CONFIG_PATH=${PKG_CONFIG_PATH}"
		echo "CGO_CPPFLAGS=${CGO_CPPFLAGS}"
		echo "CGO_CFLAGS=${CGO_CFLAGS}"
		echo "CGO_LDFLAGS=${CGO_LDFLAGS}"
	} >>"${GITHUB_ENV}"
fi
