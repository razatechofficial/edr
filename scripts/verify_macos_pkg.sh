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
"${agent_bin}" --version >/dev/null

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
