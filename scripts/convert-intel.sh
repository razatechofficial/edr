#!/usr/bin/env bash
# Merge offline baseline IOCs with downloaded raw feeds into rules/ioc/*.json|csv
# formats consumed by internal/detection/ioc (LoadFromFile).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${ROOT}/rules/ioc/baseline"
RAW="${ROOT}/rules/ioc/raw"
OUT="${ROOT}/rules/ioc"

mkdir -p "${OUT}" "${RAW}"

for f in hashes.json ips.csv domains.csv; do
	if [[ ! -f "${BASE}/${f}" ]]; then
		echo "missing baseline IOC file: ${BASE}/${f}" >&2
		exit 1
	fi
done

echo "==> IOC hashes (baseline)"
cp "${BASE}/hashes.json" "${OUT}/hashes.json"

tmp_ips="$(mktemp)"
trap 'rm -f "${tmp_ips}" "${tmp_domains:-}"' EXIT

{
	head -n1 "${BASE}/ips.csv"
	tail -n +2 "${BASE}/ips.csv"
} >"${tmp_ips}"

append_ip() {
	local addr="$1"
	local source="$2"
	local severity="${3:-high}"
	local tags="${4:-}"
	if [[ -z "${addr}" ]]; then
		return
	fi
	printf '%s,,malicious,%s,%s,,,%s\n' "${addr}" "${source}" "${severity}" "${tags}"
}

if [[ -f "${RAW}/feodotracker.txt" ]]; then
	echo "  merge feodotracker"
	while IFS= read -r line || [[ -n "${line}" ]]; do
		line="${line%%#*}"
		line="$(echo "${line}" | tr -d '[:space:]')"
		[[ "${line}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] || continue
		if [[ "${line}" == */* ]]; then
			addr="${line%/*}"
			mask="${line#*/}"
			printf '%s,%s,malicious,feodotracker,high,,,feodo\n' "${addr}" "${mask}" >>"${tmp_ips}"
		else
			append_ip "${line}" "feodotracker" "high" "feodo" >>"${tmp_ips}"
		fi
	done <"${RAW}/feodotracker.txt"
fi

if [[ -f "${RAW}/tor_exit_nodes.txt" ]]; then
	echo "  merge tor exit nodes"
	while IFS= read -r line || [[ -n "${line}" ]]; do
		line="${line%%#*}"
		line="$(echo "${line}" | tr -d '[:space:]')"
		[[ "${line}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
		append_ip "${line}" "torproject" "medium" "tor;exit" >>"${tmp_ips}"
	done <"${RAW}/tor_exit_nodes.txt"
fi

if [[ -f "${RAW}/sslbl.csv" ]]; then
	echo "  merge sslbl"
	while IFS= read -r line || [[ -n "${line}" ]]; do
		[[ "${line}" == \#* ]] && continue
		ip="$(echo "${line}" | cut -d, -f1 | tr -d '[:space:]')"
		[[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
		append_ip "${ip}" "sslbl" "high" "sslbl" >>"${tmp_ips}"
	done <"${RAW}/sslbl.csv"
fi

if [[ -f "${RAW}/spamhaus_drop.txt" ]]; then
	echo "  merge spamhaus drop"
	while IFS= read -r line || [[ -n "${line}" ]]; do
		line="$(echo "${line}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
		[[ -z "${line}" || "${line}" == \;* ]] && continue
		cidr="${line%%;*}"
		cidr="$(echo "${cidr}" | tr -d '[:space:]')"
		[[ "${cidr}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || continue
		addr="${cidr%/*}"
		mask="${cidr#*/}"
		printf '%s,%s,malicious,spamhaus-drop,high,,,drop\n' "${addr}" "${mask}" >>"${tmp_ips}"
	done <"${RAW}/spamhaus_drop.txt"
fi

{
	head -n1 "${tmp_ips}"
	tail -n +2 "${tmp_ips}" | awk -F, '!seen[$1","$2]++'
} >"${OUT}/ips.csv"
echo "  wrote ${OUT}/ips.csv ($(wc -l <"${OUT}/ips.csv" | tr -d ' ') lines)"

tmp_domains="$(mktemp)"
trap 'rm -f "${tmp_ips}" "${tmp_domains}"' EXIT

{
	head -n1 "${BASE}/domains.csv"
	tail -n +2 "${BASE}/domains.csv"
} >"${tmp_domains}"

append_domain() {
	local domain="$1"
	local source="$2"
	local severity="${3:-high}"
	local tags="${4:-}"
	domain="$(echo "${domain}" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
	[[ -z "${domain}" || "${domain}" == domain ]] && return
	printf '%s,false,malicious,%s,%s,malware,%s\n' "${domain}" "${source}" "${severity}" "${tags}"
}

if [[ -f "${RAW}/urlhaus.csv" ]]; then
	echo "  merge urlhaus"
	while IFS= read -r line || [[ -n "${line}" ]]; do
		[[ "${line}" == \"* || "${line}" == id,* ]] && continue
		# urlhaus recent CSV: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
		url="$(echo "${line}" | awk -F, '{print $3}' | tr -d '"')"
		host="$(echo "${url}" | sed -E 's|^https?://([^/:]+).*|\1|')"
		[[ "${host}" == "${url}" ]] && host="$(echo "${url}" | cut -d/ -f1)"
		append_domain "${host}" "urlhaus" "high" "urlhaus" >>"${tmp_domains}"
	done <"${RAW}/urlhaus.csv"
fi

{
	head -n1 "${tmp_domains}"
	tail -n +2 "${tmp_domains}" | awk -F, '!seen[$1]++'
} >"${OUT}/domains.csv"
echo "  wrote ${OUT}/domains.csv ($(wc -l <"${OUT}/domains.csv" | tr -d ' ') lines)"

echo "IOC convert complete"
