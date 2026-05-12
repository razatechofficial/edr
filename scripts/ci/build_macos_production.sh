#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

bash scripts/ci/setup_macos_build.sh

VERSION="${EDR_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
ARCH="$(go env GOARCH)"
AGENT_OUT="dist/darwin-${ARCH}/edr-agent"
CTL_OUT="bin/edrctl-darwin-${ARCH}"
LDFLAGS="-s -w -X main.Version=${VERSION}"

mkdir -p "dist/darwin-${ARCH}" bin
CGO_ENABLED=1 GOOS=darwin GOARCH="${ARCH}" go build -trimpath \
	-ldflags "${LDFLAGS}" -o "${AGENT_OUT}" ./cmd/agent
CGO_ENABLED=1 GOOS=darwin GOARCH="${ARCH}" go build -trimpath \
	-ldflags "${LDFLAGS}" -o "${CTL_OUT}" ./cmd/cli

otool -L "${AGENT_OUT}" | grep -E 'EndpointSecurity|Security|SystemConfiguration'

ENTITLEMENTS="build/macos/edr-agent.entitlements.plist"
if [ -n "${APPLE_SIGN_IDENTITY:-}" ] && [ -f "${ENTITLEMENTS}" ]; then
	codesign --force --options runtime --timestamp \
		--entitlements "${ENTITLEMENTS}" \
		--sign "${APPLE_SIGN_IDENTITY}" "${AGENT_OUT}"
	codesign --force --options runtime --timestamp \
		--sign "${APPLE_SIGN_IDENTITY}" "${CTL_OUT}"
	codesign -d --entitlements :- "${AGENT_OUT}" | grep -q 'com.apple.developer.endpoint-security.client'
else
	codesign --force --sign - "${AGENT_OUT}"
	codesign --force --sign - "${CTL_OUT}"
	echo "Ad-hoc signed; set APPLE_SIGN_IDENTITY for release entitlements"
fi

echo "Built production macOS agent: ${AGENT_OUT}"
