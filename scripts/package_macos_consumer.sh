#!/usr/bin/env bash
# Consumer macOS .pkg: one download like commercial AV — embedded installer only
# (trained ONNX models + rules + agent inside the binary), then unattended install +
# first-run permission wizard (TCC cannot be granted silently on macOS).
#
# Prerequisites (on macOS):
#   make build-installer-embedded
# Produces:
#   dist/edr-<version>-darwin-<arch>-consumer.pkg
#
# Optional env:
#   VERSION=...  override package version string (default: git describe).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

if ! command -v pkgbuild >/dev/null 2>&1 || ! command -v productbuild >/dev/null 2>&1; then
	echo "pkgbuild and productbuild are required (run on macOS with Xcode Command Line Tools)." >&2
	exit 1
fi

EMB="${ROOT}/bin/edr-installer-embedded"
if [[ ! -f "${EMB}" ]]; then
	echo "missing ${EMB} — run: make build-installer-embedded" >&2
	exit 1
fi

FIRSTRUN_SRC="${ROOT}/deploy/macos/first-run-permissions.sh"
PLIST_SRC="${ROOT}/deploy/macos/com.razatech.edr.firstrun.plist"
POSTINSTALL_SRC="${ROOT}/deploy/macos/postinstall-consumer.sh"
for f in "${FIRSTRUN_SRC}" "${PLIST_SRC}" "${POSTINSTALL_SRC}"; do
	if [[ ! -f "${f}" ]]; then
		echo "missing ${f}" >&2
		exit 1
	fi
done

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0")}"

case "$(uname -m)" in
arm64) ARCH=arm64 ;;
x86_64) ARCH=amd64 ;;
*)
	echo "unsupported architecture: $(uname -m)" >&2
	exit 1
	;;
esac

xml_escape() {
	printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

VER_XML="$(xml_escape "${VERSION}")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/edr-pkg-consumer.XXXXXX")"
STAGE="${WORK}/stage"
SCRIPTS="${WORK}/scripts"
mkdir -p "${STAGE}/usr/local/bin" "${STAGE}/Library/Application Support/EDR" "${STAGE}/Library/LaunchAgents" "${SCRIPTS}"

cp "${EMB}" "${STAGE}/usr/local/bin/edr-installer"
chmod 755 "${STAGE}/usr/local/bin/edr-installer"

cp "${FIRSTRUN_SRC}" "${STAGE}/Library/Application Support/EDR/first-run-permissions.sh"
chmod 755 "${STAGE}/Library/Application Support/EDR/first-run-permissions.sh"

cp "${PLIST_SRC}" "${STAGE}/Library/LaunchAgents/com.razatech.edr.firstrun.plist"
chmod 644 "${STAGE}/Library/LaunchAgents/com.razatech.edr.firstrun.plist"

cp "${POSTINSTALL_SRC}" "${SCRIPTS}/postinstall"
chmod 755 "${SCRIPTS}/postinstall"

cat > "${SCRIPTS}/preinstall" <<'PRE'
#!/bin/bash
set -e
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
if [[ -x /bin/launchctl ]]; then LC=/bin/launchctl
elif [[ -x /usr/bin/launchctl ]]; then LC=/usr/bin/launchctl
else LC=launchctl
fi
AGENT_PLIST="/Library/LaunchDaemons/com.razatech.edr-agent.plist"
if "${LC}" print "system/com.razatech.edr-agent" &>/dev/null; then
	"${LC}" bootout system "${AGENT_PLIST}" 2>/dev/null || true
fi
"${LC}" unload "${AGENT_PLIST}" 2>/dev/null || true
PRE
chmod 755 "${SCRIPTS}/preinstall"

COMPONENT="${WORK}/edr-consumer-component.pkg"
mkdir -p "${ROOT}/dist"

pkgbuild \
	--root "${STAGE}" \
	--scripts "${SCRIPTS}" \
	--identifier "com.razatech.edr.consumer" \
	--version "${VERSION}" \
	--install-location "/" \
	--ownership recommended \
	"${COMPONENT}"

DIST_XML="${WORK}/distribution.xml"
cat > "${DIST_XML}" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
	<title>EDR — embedded ML models (consumer install)</title>
	<domains enable_localSystem="true"/>
	<options customize="never" require-scripts="false" rootVolumeOnly="true"/>
	<choices-outline>
		<line choice="com.razatech.edr.consumer"/>
	</choices-outline>
	<choice id="com.razatech.edr.consumer" visible="false">
		<pkg-ref id="com.razatech.edr.consumer"/>
	</choice>
	<pkg-ref id="com.razatech.edr.consumer" version="${VER_XML}" onConclusion="none">edr-consumer-component.pkg</pkg-ref>
</installer-gui-script>
EOF

OUT_SAFE_VER="${VERSION//\//-}"
OUT="${ROOT}/dist/edr-${OUT_SAFE_VER}-darwin-${ARCH}-consumer.pkg"
productbuild --distribution "${DIST_XML}" --package-path "${WORK}" "${OUT}"

rm -rf "${WORK}"
echo "${OUT}"
