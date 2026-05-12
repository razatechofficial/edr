#!/usr/bin/env bash

resolve_bpftool_bin() {
	local kernel tools_dir tool

	kernel="$(uname -r)"
	tool="/usr/lib/linux-tools/${kernel}/bpftool"
	if [ -x "${tool}" ]; then
		echo "${tool}"
		return 0
	fi

	for tools_dir in /usr/lib/linux-tools/* /usr/lib/linux-tools-*; do
		[ -d "${tools_dir}" ] || continue
		tool="${tools_dir}/bpftool"
		if [ -x "${tool}" ]; then
			echo "${tool}"
			return 0
		fi
	done

	if [ -x /usr/local/bin/bpftool ] && /usr/local/bin/bpftool version >/dev/null 2>&1; then
		echo /usr/local/bin/bpftool
		return 0
	fi

	if command -v bpftool >/dev/null 2>&1 && bpftool version >/dev/null 2>&1; then
		command -v bpftool
		return 0
	fi

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
