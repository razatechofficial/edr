#!/usr/bin/env bash
# Verify a built macOS .pkg is a complete native installer:
# EDR Agent.app (console) + sensor + LaunchDaemon + models + thin edr-installer.
set -euo pipefail

PKG_PATH="${1:-}"
if [[ -z "${PKG_PATH}" ]]; then
	echo "usage: $0 dist/edr-agent_<version>_<arch>.pkg" >&2
	exit 1
fi
if [[ ! -f "${PKG_PATH}" ]]; then
	echo "package not found: ${PKG_PATH}" >&2
	exit 1
fi
if ! command -v pkgutil >/dev/null 2>&1; then
	echo "pkgutil required (run on macOS)" >&2
	exit 1
fi

base="$(basename "${PKG_PATH}")"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
pkgutil --expand-full "${PKG_PATH}" "${tmpdir}/expanded"

find_payload() {
	find "${tmpdir}/expanded" -path "$1" -print -quit
}

required=(
	"*/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui"
	"*/Applications/EDR Agent.app/Contents/MacOS/edrctl"
	"*/usr/local/bin/edrctl"
	"*/usr/local/bin/edr-installer"
	"*/Library/Application Support/EDR/config/agent.yaml"
	"*/Library/Application Support/EDR/config/config.tenant.yml"
	"*/Library/Application Support/EDR/config/config.tenant.tls.yml"
	"*/Library/Application Support/EDR/config/config.fleet.tls.yml"
	"*/Library/Application Support/EDR/config/rules/baseline.yaml"
	"*/Library/Application Support/EDR/config/rules/yara/exploits/cve_2021_44228_log4j.yar"
	"*/Library/LaunchDaemons/com.razatech.edr-agent.plist"
	"*/Library/Application Support/EDR/models/manifest.json"
)

for pattern in "${required[@]}"; do
	if [[ -z "$(find_payload "${pattern}")" ]]; then
		echo "missing required packaged path: ${pattern}" >&2
		echo "payload tree:" >&2
		find "${tmpdir}/expanded" -print | head -n 80 >&2
		exit 1
	fi
done

# Console must stay thin: the fat embedbundle installer belongs on attended-setup.
fat_in_app="$(find_payload '*/Applications/EDR Agent.app/Contents/MacOS/edr-installer')"
if [[ -n "${fat_in_app}" ]]; then
	echo "EDR Agent.app must not embed edr-installer (use /usr/local/bin/edr-installer)" >&2
	exit 1
fi

agent_bin="$(find "${tmpdir}/expanded" -path '*/usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent' -print -quit)"
if [[ -z "${agent_bin}" ]]; then
	agent_bin="$(find "${tmpdir}/expanded" -path '*/usr/local/bin/edr-agent' -print -quit)"
fi
if [[ -z "${agent_bin}" ]]; then
	echo "missing edr-agent binary in pkg payload" >&2
	exit 1
fi

want_arch=""
case "${base}" in
*_amd64.pkg|*_intel.pkg|*darwin-amd64*) want_arch=x86_64 ;;
*_arm64.pkg|*_apple-silicon.pkg|*darwin-arm64*) want_arch=arm64 ;;
esac

check_arch() {
	local bin="$1"
	local label="$2"
	if [[ -z "${bin}" || -z "${want_arch}" ]] || ! command -v lipo >/dev/null 2>&1; then
		return 0
	fi
	local got
	got="$(lipo -archs "${bin}" 2>/dev/null || true)"
	if ! grep -qw "${want_arch}" <<<"${got}"; then
		echo "${label} should contain ${want_arch}, lipo reported: ${got:-unknown} (${bin})" >&2
		exit 1
	fi
}

# Console/installer must not link Homebrew YARA. The sensor may link a
# bundled libyara.dylib under @executable_path/../Frameworks.
check_no_homebrew_yara() {
	local bin="$1"
	local label="$2"
	if [[ -z "${bin}" ]] || ! command -v otool >/dev/null 2>&1; then
		return 0
	fi
	if otool -L "${bin}" | grep -Eiq '/opt/yara/|/Cellar/yara/|/usr/local/opt/yara/'; then
		echo "${label} must not link Homebrew libyara" >&2
		otool -L "${bin}" >&2 || true
		exit 1
	fi
}

if [[ -n "${want_arch}" ]] && command -v lipo >/dev/null 2>&1; then
	check_arch "${agent_bin}" "edr-agent"
	check_no_homebrew_yara "${agent_bin}" "edr-agent"
	ui_bin="$(find_payload '*/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui')"
	ctl_app="$(find_payload '*/Applications/EDR Agent.app/Contents/MacOS/edrctl')"
	inst_bin="$(find_payload '*/usr/local/bin/edr-installer')"
	check_arch "${ui_bin}" "EDR Agent.app UI"
	check_arch "${ctl_app}" "EDR Agent.app edrctl"
	check_arch "${inst_bin}" "usr/local/bin/edr-installer"
	check_arch "$(find_payload '*/usr/local/bin/edrctl')" "usr/local/bin/edrctl"
	check_no_homebrew_yara "${ui_bin}" "EDR Agent.app UI"
	check_no_homebrew_yara "${ctl_app}" "EDR Agent.app edrctl"
	check_no_homebrew_yara "${inst_bin}" "usr/local/bin/edr-installer"
	check_no_homebrew_yara "$(find_payload '*/usr/local/bin/edrctl')" "usr/local/bin/edrctl"
fi

dist="$(find "${tmpdir}/expanded" -name Distribution -print -quit)"
if [[ -n "${dist}" && -n "${want_arch}" ]]; then
	if ! grep -q "hostArchitectures=\"${want_arch}\"" "${dist}"; then
		echo "Distribution.xml must set hostArchitectures=${want_arch} so the wrong CPU cannot install this pkg" >&2
		exit 1
	fi
fi

cfg="$(find "${tmpdir}/expanded" -path '*/Library/Application Support/EDR/config/agent.yaml' -print -quit)"
if [[ -z "${cfg}" ]]; then
	echo "missing staged agent.yaml" >&2
	exit 1
fi
if ! awk '
  $0 ~ /^ml:/ { in_ml=1; next }
  in_ml && /^[^ ]/ { in_ml=0 }
  in_ml && $0 ~ /enabled: true/ { found=1 }
  END { exit found ? 0 : 1 }
' "${cfg}"; then
	echo "agent.yaml must set ml.enabled: true" >&2
	exit 1
fi
onnx_dir="$(find "${tmpdir}/expanded" -type d -path '*/models' 2>/dev/null | head -1)"
if [[ -z "${onnx_dir}" ]]; then
	echo "missing models directory in pkg" >&2
	exit 1
fi
required_models=(
	behavior_lstm.onnx
	network_anomaly.onnx
	ransomware.onnx
	network_lgbm.onnx
	rat_c2_detector.onnx
)
for m in "${required_models[@]}"; do
	if [[ ! -f "${onnx_dir}/${m}" ]]; then
		echo "missing required ONNX model: ${m}" >&2
		exit 1
	fi
done
if [[ -f "${onnx_dir}/aigen_detector.onnx" ]]; then
	echo "aigen_detector.onnx must not ship in the default macOS package" >&2
	exit 1
fi
if [[ -f "${onnx_dir}/pe_classifier.onnx" ]]; then
	echo "pe_classifier.onnx is Windows-only and must not ship in the macOS package" >&2
	exit 1
fi
onnx_count="$(find "${onnx_dir}" -name '*.onnx' 2>/dev/null | wc -l | tr -d ' ')"
if [ "${onnx_count}" -lt "${#required_models[@]}" ]; then
	echo "expected at least ${#required_models[@]} ONNX models in pkg, found ${onnx_count}" >&2
	exit 1
fi

echo "macOS package verification passed: ${PKG_PATH}"
