#!/usr/bin/env bash
# Verify a built macOS .pkg includes fleet rollout profiles and core agent paths.
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

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
pkgutil --expand-full "${PKG_PATH}" "${tmpdir}/expanded"

find_payload() {
	find "${tmpdir}/expanded" -path "$1" -print -quit
}

required=(
	"*/Library/Application Support/EDR/config/agent.yaml"
	"*/Library/Application Support/EDR/config/config.tenant.yml"
	"*/Library/Application Support/EDR/config/config.tenant.tls.yml"
	"*/Library/Application Support/EDR/config/config.fleet.tls.yml"
	"*/Library/Application Support/EDR/config/rules/baseline.yaml"
	"*/Library/Application Support/EDR/config/rules/yara/exploits/cve_2021_44228_log4j.yar"
	"*/Library/LaunchDaemons/com.razatech.edr-agent.plist"
	"*/Library/Application Support/EDR/models/manifest.json"
	"*/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui"
	"*/usr/local/bin/edrctl"
)

for pattern in "${required[@]}"; do
	if [[ -z "$(find_payload "${pattern}")" ]]; then
		echo "missing required packaged path: ${pattern}" >&2
		exit 1
	fi
done

agent_bin="$(find "${tmpdir}/expanded" -path '*/edr-agent.app/Contents/MacOS/edr-agent' -print -quit)"
if [[ -z "${agent_bin}" ]]; then
	agent_bin="$(find "${tmpdir}/expanded" -path '*/usr/local/bin/edr-agent' -print -quit)"
fi
if [[ -z "${agent_bin}" ]]; then
	echo "missing edr-agent binary in pkg payload" >&2
	exit 1
fi

base="$(basename "${PKG_PATH}")"
want_arch=""
case "${base}" in
*_amd64.pkg|*_intel.pkg|*darwin-amd64*) want_arch=x86_64 ;;
*_arm64.pkg|*_apple-silicon.pkg|*darwin-arm64*) want_arch=arm64 ;;
esac
if [[ -n "${want_arch}" ]] && command -v lipo >/dev/null 2>&1; then
	got="$(lipo -archs "${agent_bin}" 2>/dev/null || true)"
	if ! grep -qw "${want_arch}" <<<"${got}"; then
		echo "package ${base} should contain ${want_arch}, lipo reported: ${got:-unknown}" >&2
		exit 1
	fi
	ui_bin="$(find_payload '*/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui')"
	if [[ -n "${ui_bin}" ]]; then
		ui_got="$(lipo -archs "${ui_bin}" 2>/dev/null || true)"
		if ! grep -qw "${want_arch}" <<<"${ui_got}"; then
			echo "EDR Agent.app should contain ${want_arch}, lipo reported: ${ui_got:-unknown}" >&2
			exit 1
		fi
	fi
else
	"${agent_bin}" --version >/dev/null
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
onnx_count="$(find "${tmpdir}/expanded" \( -iname '*.onnx' -o -iname '*.onn' \) | wc -l | tr -d ' ')"
if [ "${onnx_count}" -lt 12 ]; then
	echo "expected 12 ONNX models in pkg, found ${onnx_count}" >&2
	exit 1
fi

echo "macOS package verification passed: ${PKG_PATH}"
