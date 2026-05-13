#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

# shellcheck source=scripts/ci/setup_macos_build.sh
source "${ROOT}/scripts/ci/setup_macos_build.sh"

export CGO_ENABLED=1
# Ensure CGO sees the active macOS SDK (framework search paths).
if [ -z "${SDKROOT:-}" ] && command -v xcrun >/dev/null 2>&1; then
	_sdk="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
	if [ -n "${_sdk}" ]; then
		export SDKROOT="${_sdk}"
	fi
fi
if command -v xcrun >/dev/null 2>&1; then
	_clang="$(xcrun --find clang 2>/dev/null || true)"
	if [ -n "${_clang}" ]; then
		export CC="${_clang}"
	fi
fi

# Match the host ABI (GitHub-hosted macOS is arm64). A mismatched GOARCH breaks
# EndpointSecurity / YARA CGO links when the toolchain targets the wrong slice.
case "${EDR_MACOS_ARCH:-$(uname -m)}" in
arm64 | aarch64) export GOARCH=arm64 ;;
amd64 | x86_64) export GOARCH=amd64 ;;
*) export GOARCH="${GOARCH:-$(go env GOARCH)}" ;;
esac

VERSION="${EDR_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
ARCH="${GOARCH}"
AGENT_OUT="dist/darwin-${ARCH}/edr-agent"
CTL_OUT="bin/edrctl-darwin-${ARCH}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.Version=${VERSION}"

mkdir -p "dist/darwin-${ARCH}" bin
if ! CGO_ENABLED=1 GOOS=darwin GOARCH="${ARCH}" go build -trimpath -v \
	-ldflags "${LDFLAGS}" -o "${AGENT_OUT}" ./cmd/agent; then
	echo "macOS agent build failed" >&2
	exit 1
fi
if ! CGO_ENABLED=1 GOOS=darwin GOARCH="${ARCH}" go build -trimpath \
	-ldflags "${LDFLAGS}" -o "${CTL_OUT}" ./cmd/cli; then
	CGO_ENABLED=0 GOOS=darwin GOARCH="${ARCH}" go build -trimpath \
		-ldflags "${LDFLAGS}" -o "${CTL_OUT}" ./cmd/cli
fi

if ! otool -L "${AGENT_OUT}" | grep -Eiq 'EndpointSecurity|/System/Library/Frameworks/Security\.framework'; then
	echo "expected macOS security frameworks are not linked into ${AGENT_OUT}" >&2
	otool -L "${AGENT_OUT}" >&2 || true
	exit 1
fi

ENTITLEMENTS="build/macos/edr-agent.entitlements.plist"
if [ -n "${APPLE_SIGN_IDENTITY:-}" ] && [ -f "${ENTITLEMENTS}" ]; then
	if ! codesign --force --options runtime --timestamp \
		--entitlements "${ENTITLEMENTS}" \
		--sign "${APPLE_SIGN_IDENTITY}" "${AGENT_OUT}"; then
		echo "codesign with APPLE_SIGN_IDENTITY failed" >&2
		exit 1
	fi
	if ! codesign --force --options runtime --timestamp \
		--sign "${APPLE_SIGN_IDENTITY}" "${CTL_OUT}"; then
		echo "codesign for edrctl failed" >&2
		exit 1
	fi
	if ! codesign -d --entitlements :- "${AGENT_OUT}" | grep -q 'com.apple.developer.endpoint-security.client'; then
		echo "endpoint-security entitlement missing after signing" >&2
		exit 1
	fi
else
	codesign --force --sign - "${AGENT_OUT}" || echo "warning: ad-hoc codesign skipped for ${AGENT_OUT}" >&2
	codesign --force --sign - "${CTL_OUT}" || echo "warning: ad-hoc codesign skipped for ${CTL_OUT}" >&2
	echo "Ad-hoc signed; set APPLE_SIGN_IDENTITY for release entitlements"
fi

echo "Built production macOS agent: ${AGENT_OUT}"
