#!/usr/bin/env bash
set -euo pipefail

if ! command -v brew >/dev/null 2>&1 && [[ ! -x /usr/local/bin/brew ]]; then
	echo "Homebrew is required on macOS build runners" >&2
	exit 1
fi

export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_INSTALL_CLEANUP=1

case "${EDR_MACOS_ARCH:-$(uname -m)}" in
arm64 | aarch64) TARGET_ARCH=arm64 ;;
amd64 | x86_64) TARGET_ARCH=amd64 ;;
*)
	echo "unsupported EDR_MACOS_ARCH=${EDR_MACOS_ARCH:-}" >&2
	exit 1
	;;
esac

HOST_ARCH="$(uname -m)"
case "${HOST_ARCH}" in
arm64 | aarch64) HOST_ARCH=arm64 ;;
x86_64) HOST_ARCH=amd64 ;;
esac

# macos_run_build.sh wraps amd64 builds in arch -x86_64; uname then reports x86_64 on
# Apple Silicon hosts, so also honor EDR_MACOS_USE_ROSETTA / proc_translated.
USE_ROSETTA=0
if [[ "${EDR_MACOS_USE_ROSETTA:-}" == "1" ]] || [[ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" == "1" ]]; then
	USE_ROSETTA=1
elif [[ "${TARGET_ARCH}" == "amd64" && "${HOST_ARCH}" == "arm64" ]]; then
	USE_ROSETTA=1
fi

BREW=(brew)
if [[ "${USE_ROSETTA}" == "1" ]]; then
	# Rosetta path: only reachable on an Apple Silicon host, and it needs an
	# x86_64 Homebrew in /usr/local. Homebrew's installer refuses to create
	# one on Apple Silicon ("Homebrew on macOS is only supported on Apple
	# Silicon processors!"), so this cannot bootstrap itself any more — it
	# works only where /usr/local/bin/brew already exists. CI builds amd64
	# on a native Intel runner (macos-15-intel) instead, where USE_ROSETTA
	# is 0 and this branch is not taken.
	if [[ ! -x /usr/local/bin/brew ]]; then
		echo "ERROR: amd64 macOS build needs an x86_64 Homebrew at /usr/local/bin/brew." >&2
		echo "       Homebrew will not install one on an Apple Silicon host; build this slice" >&2
		echo "       on a native Intel macOS machine or runner (e.g. macos-15-intel)." >&2
		exit 1
	fi
	eval "$(/usr/local/bin/brew shellenv)"
	BREW=(arch -x86_64 /usr/local/bin/brew)
	export EDR_MACOS_USE_ROSETTA=1
fi

install_brew_pkg() {
	local pkg="$1"
	if ! "${BREW[@]}" list "${pkg}" >/dev/null 2>&1; then
		"${BREW[@]}" install "${pkg}"
	fi
}

for pkg in yara pkg-config openssl@3 libmagic jansson; do
	install_brew_pkg "${pkg}"
done

yara_prefix="$("${BREW[@]}" --prefix yara)"
openssl_prefix="$("${BREW[@]}" --prefix openssl@3)"
export PKG_CONFIG_PATH="${yara_prefix}/lib/pkgconfig:${openssl_prefix}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export CGO_ENABLED=1
export CGO_CPPFLAGS="${CGO_CPPFLAGS:-} -I${openssl_prefix}/include"
export CGO_CFLAGS="${CGO_CFLAGS:-} $(PKG_CONFIG_PATH="${PKG_CONFIG_PATH}" pkg-config --cflags yara 2>/dev/null || true)"
export CGO_LDFLAGS="${CGO_LDFLAGS:-} $(PKG_CONFIG_PATH="${PKG_CONFIG_PATH}" pkg-config --libs yara 2>/dev/null || true) -L${openssl_prefix}/lib"

if ! PKG_CONFIG_PATH="${PKG_CONFIG_PATH}" pkg-config --exists yara; then
	echo "ERROR: yara pkg-config metadata not found after brew install (arch=${TARGET_ARCH})" >&2
	exit 1
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
	{
		echo "EDR_MACOS_ARCH=${TARGET_ARCH}"
		echo "CGO_ENABLED=1"
		echo "PKG_CONFIG_PATH=${PKG_CONFIG_PATH}"
		echo "CGO_CPPFLAGS=${CGO_CPPFLAGS}"
		echo "CGO_CFLAGS=${CGO_CFLAGS}"
		echo "CGO_LDFLAGS=${CGO_LDFLAGS}"
		echo "EDR_MACOS_USE_ROSETTA=${EDR_MACOS_USE_ROSETTA:-0}"
	} >>"${GITHUB_ENV}"
fi

echo "macOS build deps ready: target=${TARGET_ARCH} host=${HOST_ARCH} rosetta=${EDR_MACOS_USE_ROSETTA:-0}"
