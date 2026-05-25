#!/usr/bin/env bash
# Bundle Homebrew YARA and its transitive dylibs for Hardened Runtime.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARY="${1:-}"
if [[ -z "${BINARY}" || ! -f "${BINARY}" ]]; then
	echo "usage: macos_bundle_dylibs.sh path/to/edr-agent" >&2
	exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
	echo "Homebrew required to locate libyara for bundling" >&2
	exit 1
fi

BREW_PREFIX="$(brew --prefix)"
YARA_LIB="${BREW_PREFIX}/opt/yara/lib/libyara.10.dylib"
if [[ ! -f "${YARA_LIB}" ]]; then
	echo "missing ${YARA_LIB}; run: brew install yara" >&2
	exit 1
fi

BIN_DIR="$(cd "$(dirname "${BINARY}")" && pwd)"
LIB_DIR="${BIN_DIR}/../Frameworks"
mkdir -p "${LIB_DIR}"

bundle_dylib() {
	local src="$1"
	local base
	base="$(basename "${src}")"
	local dest="${LIB_DIR}/${base}"
	cp -f "${src}" "${dest}"
	chmod 755 "${dest}"
}

DEPS=(
	"${BREW_PREFIX}/opt/yara/lib/libyara.10.dylib"
	"${BREW_PREFIX}/opt/openssl@3/lib/libcrypto.3.dylib"
	"${BREW_PREFIX}/opt/libmagic/lib/libmagic.1.dylib"
	"${BREW_PREFIX}/opt/jansson/lib/libjansson.4.dylib"
)

for dep in "${DEPS[@]}"; do
	if [[ ! -f "${dep}" ]]; then
		echo "missing ${dep}; run: brew install yara openssl@3 libmagic jansson" >&2
		exit 1
	fi
	bundle_dylib "${dep}" >/dev/null
done

YARA_DEST="${LIB_DIR}/libyara.10.dylib"
CRYPTO_DEST="${LIB_DIR}/libcrypto.3.dylib"
MAGIC_DEST="${LIB_DIR}/libmagic.1.dylib"
JANSSON_DEST="${LIB_DIR}/libjansson.4.dylib"
YARA_LINK='@executable_path/../Frameworks/libyara.10.dylib'
LEGACY_LINK='@executable_path/../lib/edr/libyara.10.dylib'

install_name_tool -id '@loader_path/libyara.10.dylib' "${YARA_DEST}"
install_name_tool -change "${BREW_PREFIX}/opt/openssl@3/lib/libcrypto.3.dylib" '@loader_path/libcrypto.3.dylib' "${YARA_DEST}"
install_name_tool -change "${BREW_PREFIX}/opt/libmagic/lib/libmagic.1.dylib" '@loader_path/libmagic.1.dylib' "${YARA_DEST}"
install_name_tool -change "${BREW_PREFIX}/opt/jansson/lib/libjansson.4.dylib" '@loader_path/libjansson.4.dylib' "${YARA_DEST}"

install_name_tool -id '@loader_path/libcrypto.3.dylib' "${CRYPTO_DEST}"
install_name_tool -id '@loader_path/libmagic.1.dylib' "${MAGIC_DEST}"
install_name_tool -id '@loader_path/libjansson.4.dylib' "${JANSSON_DEST}"

if otool -L "${BINARY}" | grep -q "${YARA_LINK}"; then
	echo "YARA already linked in ${BINARY}"
elif otool -L "${BINARY}" | grep -q "${LEGACY_LINK}"; then
	install_name_tool -change "${LEGACY_LINK}" "${YARA_LINK}" "${BINARY}"
else
	install_name_tool -change "${YARA_LIB}" "${YARA_LINK}" "${BINARY}"
fi

if [[ -n "${APPLE_SIGN_IDENTITY:-}" ]]; then
	for dylib in "${DEPS[@]}"; do
		dest="${LIB_DIR}/$(basename "${dylib}")"
		codesign --force --options runtime --timestamp \
			--sign "${APPLE_SIGN_IDENTITY}" "${dest}"
	done
fi

echo "Bundled YARA deps in ${LIB_DIR}:"
ls -1 "${LIB_DIR}"
echo "Agent links:"
otool -L "${BINARY}" | grep -E 'yara|Frameworks' || true
