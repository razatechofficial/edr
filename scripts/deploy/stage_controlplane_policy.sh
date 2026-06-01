#!/usr/bin/env bash
# Stage signed rule bundles for the control plane policy store.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POLICY_DIR="${1:-${EDR_CONTROLPLANE_POLICY_DIR:-/var/lib/edr-controlplane/policy}}"
RULES_ROOT="${2:-${ROOT}/rules}"
VERSION="${EDR_POLICY_VERSION:-$(date -u +%Y.%m.%d)}"
SIGN_KEY="${EDR_POLICY_SIGN_KEY:-}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "ERROR: Run as root (sudo) when writing ${POLICY_DIR}." >&2
	exit 1
fi

bundle_hash() {
	local file="$1"
	local sum
	sum="$(sha256sum "${file}" | awk '{print $1}')"
	printf 'sha256:%s' "${sum}"
}

bundle_signature() {
	local file="$1"
	if [[ -z "${SIGN_KEY}" ]]; then
		return 0
	fi
	(
		cd "${ROOT}"
		go run ./tools/sign_policy_bundle/main.go -key "${SIGN_KEY}" "${file}"
	)
}

write_bundle() {
	local name="$1"
	local archive="$2"
	shift 2
	local paths=("$@")
	local out="${POLICY_DIR}/${archive}"

	if [[ ${#paths[@]} -eq 0 ]]; then
		echo "skip empty bundle ${name}" >&2
		return 1
	fi

	for path in "${paths[@]}"; do
		if [[ ! -e "${path}" ]]; then
			echo "missing rules path: ${path}" >&2
			exit 1
		fi
	done

	tar -czf "${out}" -C "${RULES_ROOT}" "${paths[@]}"
	chmod 0640 "${out}"
	local sig=""
	if [[ -n "${SIGN_KEY}" ]]; then
		sig="$(bundle_signature "${out}")"
	fi
	printf '%s\n' "${name}|${VERSION}|tar.gz|${archive}|$(bundle_hash "${out}")|${sig}"
}

install -d -m 0750 "${POLICY_DIR}"
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "${TMP_MANIFEST}"' EXIT

{
	write_bundle "yara-exploits" "yara-exploits.tar.gz" "yara/exploits"
	write_bundle "yara-malware-probes" "yara-malware-probes.tar.gz" "yara/malware/eicar.yar" "yara/malware/cobalt_strike.yar"
	write_bundle "sigma-linux-core" "sigma-linux-core.tar.gz" "sigma/linux/execution" "sigma/linux/defense_evasion" "sigma/linux/discovery"
	write_bundle "sigma-macos" "sigma-macos.tar.gz" "sigma/macos"
	write_bundle "sigma-windows-process" "sigma-windows-process.tar.gz" "sigma/windows/process_creation"
	if [[ -f "${RULES_ROOT}/ioc/hashes.json" && -f "${RULES_ROOT}/ioc/ips.csv" && -f "${RULES_ROOT}/ioc/domains.csv" ]]; then
		ioc_paths=(ioc/hashes.json ioc/ips.csv ioc/domains.csv)
		if [[ -f "${RULES_ROOT}/ioc/kev.json" ]]; then
			ioc_paths+=(ioc/kev.json)
		fi
		write_bundle "ioc-offline" "ioc-offline.tar.gz" "${ioc_paths[@]}"
	fi
	if [[ -d "${RULES_ROOT}/compliance/sca/linux" ]]; then
		write_bundle "sca-linux" "sca-linux.tar.gz" "compliance/sca/linux"
	fi
	if [[ -d "${RULES_ROOT}/compliance/sca/windows" ]]; then
		write_bundle "sca-windows" "sca-windows.tar.gz" "compliance/sca/windows"
	fi
	if [[ -d "${RULES_ROOT}/compliance/sca/darwin" ]]; then
		write_bundle "sca-macos" "sca-macos.tar.gz" "compliance/sca/darwin"
	fi
} > "${TMP_MANIFEST}"

python3 - <<'PY' "${TMP_MANIFEST}" "${POLICY_DIR}/manifest.json"
import json, sys

bundles = []
with open(sys.argv[1], encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        name, version, fmt, file_name, digest = parts[:5]
        entry = {
            "name": name,
            "version": version,
            "format": fmt,
            "file": file_name,
            "hash": digest,
        }
        if len(parts) > 5 and parts[5]:
            entry["signature"] = parts[5]
        bundles.append(entry)

with open(sys.argv[2], "w", encoding="utf-8") as out:
    json.dump({"bundles": bundles}, out, indent=2)
    out.write("\n")
PY

chmod 0640 "${POLICY_DIR}/manifest.json"
echo "policy staged under ${POLICY_DIR}"
if [[ -n "${SIGN_KEY}" ]]; then
	echo "  bundles signed with EDR_POLICY_SIGN_KEY"
else
	echo "  bundles unsigned (set EDR_POLICY_SIGN_KEY to sign for production agents)"
fi
echo "  restart control plane: sudo systemctl restart edr-controlplane"
echo "  verify: bash scripts/pilot/verify_controlplane_policy.sh"
