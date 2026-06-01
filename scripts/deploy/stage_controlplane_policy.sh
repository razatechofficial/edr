#!/usr/bin/env bash
# Stage signed rule bundles for the control plane policy store.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POLICY_DIR="${1:-${EDR_CONTROLPLANE_POLICY_DIR:-/var/lib/edr-controlplane/policy}}"
RULES_ROOT="${2:-${ROOT}/rules}"
VERSION="${EDR_POLICY_VERSION:-$(date -u +%Y.%m.%d)}"

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
	printf '%s\n' "${name}|${VERSION}|tar.gz|${archive}|$(bundle_hash "${out}")"
}

install -d -m 0750 "${POLICY_DIR}"
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "${TMP_MANIFEST}"' EXIT

{
	write_bundle "yara-exploits" "yara-exploits.tar.gz" "yara/exploits"
	write_bundle "yara-malware-probes" "yara-malware-probes.tar.gz" "yara/malware/eicar.yar" "yara/malware/cobalt_strike.yar"
} > "${TMP_MANIFEST}"

python3 - <<'PY' "${TMP_MANIFEST}" "${POLICY_DIR}/manifest.json"
import json, sys

bundles = []
with open(sys.argv[1], encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        name, version, fmt, file_name, digest = line.split("|", 4)
        bundles.append({
            "name": name,
            "version": version,
            "format": fmt,
            "file": file_name,
            "hash": digest,
        })

with open(sys.argv[2], "w", encoding="utf-8") as out:
    json.dump({"bundles": bundles}, out, indent=2)
    out.write("\n")
PY

chmod 0640 "${POLICY_DIR}/manifest.json"
echo "policy staged under ${POLICY_DIR}"
echo "  restart control plane: sudo systemctl restart edr-controlplane"
echo "  verify: bash scripts/pilot/verify_controlplane_policy.sh"
