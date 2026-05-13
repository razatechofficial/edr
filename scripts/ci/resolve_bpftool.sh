#!/usr/bin/env bash

# Emit bpftool paths to try, best-first: exact linux-tools-$(uname -r), then other
# installed toolchains, then /usr/local/bin and PATH.
bpftool_candidates() {
	local k tools_dir t base
	k="$(uname -r)"
	t="/usr/lib/linux-tools/${k}/bpftool"
	if [ -x "${t}" ]; then
		echo "${t}"
	fi
	for tools_dir in /usr/lib/linux-tools/*/; do
		[ -d "${tools_dir}" ] || continue
		base="${tools_dir%/}"
		base="${base##*/}"
		[ "${base}" = "${k}" ] && continue
		t="${tools_dir}bpftool"
		if [ -x "${t}" ]; then
			echo "${t}"
		fi
	done
	if [ -x /usr/local/bin/bpftool ]; then
		echo /usr/local/bin/bpftool
	fi
	if command -v bpftool >/dev/null 2>&1; then
		command -v bpftool
	fi
}

# First bpftool that runs `version` and can read running-kernel BTF (when present).
resolve_bpftool_for_btf_dump() {
	local cand
	if [ ! -f /sys/kernel/btf/vmlinux ]; then
		return 1
	fi
	while IFS= read -r cand; do
		[ -n "${cand}" ] || continue
		[ -x "${cand}" ] || continue
		if ! "${cand}" version >/dev/null 2>&1; then
			continue
		fi
		if "${cand}" btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | head -c 65536 | grep -q 'struct '; then
			echo "${cand}"
			return 0
		fi
	done < <(bpftool_candidates | awk '!a[$0]++')
	return 1
}

resolve_bpftool_bin() {
	local cand

	if [ -f /sys/kernel/btf/vmlinux ]; then
		if cand="$(resolve_bpftool_for_btf_dump)"; then
			echo "${cand}"
			return 0
		fi
	fi

	while IFS= read -r cand; do
		[ -n "${cand}" ] || continue
		[ -x "${cand}" ] || continue
		if "${cand}" version >/dev/null 2>&1; then
			echo "${cand}"
			return 0
		fi
	done < <(bpftool_candidates | awk '!a[$0]++')

	return 1
}

install_bpftool_path() {
	local bpftool_bin

	if ! bpftool_bin="$(resolve_bpftool_bin)"; then
		echo "ERROR: bpftool is not available for kernel $(uname -r)" >&2
		return 1
	fi

	sudo ln -sf "${bpftool_bin}" /usr/local/bin/bpftool
	export PATH="/usr/local/bin:${PATH}"
	if ! bpftool version >/dev/null 2>&1; then
		echo "ERROR: installed bpftool is not runnable: ${bpftool_bin}" >&2
		return 1
	fi
}
