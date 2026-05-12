#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

sudo apt-get update -qq

if ! sudo apt-get install -y clang-16 llvm-16 libbpf-dev libyara-dev pkg-config linux-tools-common linux-tools-generic; then
	sudo apt-get install -y clang llvm libbpf-dev libyara-dev pkg-config linux-tools-common linux-tools-generic
fi

for opt in "linux-tools-$(uname -r)" "linux-cloud-tools-$(uname -r)" "linux-headers-$(uname -r)"; do
	sudo apt-get install -y "${opt}" || true
done

if ! pkg-config --exists libbpf 2>/dev/null; then
	bash scripts/install_libbpf_headers.sh
fi

clang_bpf=""
for candidate in clang-16 clang-17 clang; do
	if command -v "${candidate}" >/dev/null 2>&1 && \
		"${candidate}" --target=bpf -print-targets 2>&1 | grep -q bpf; then
		clang_bpf="${candidate}"
		break
	fi
done
if [ -z "${clang_bpf}" ]; then
	echo "ERROR: no BPF-capable clang found" >&2
	exit 1
fi

if command -v bpftool >/dev/null 2>&1 && ! bpftool version >/dev/null 2>&1; then
	sudo rm -f /usr/local/bin/bpftool
fi

kernel="$(uname -r)"
if [ -x "/usr/lib/linux-tools/${kernel}/bpftool" ]; then
	sudo ln -sf "/usr/lib/linux-tools/${kernel}/bpftool" /usr/local/bin/bpftool
else
	for tools_dir in /usr/lib/linux-tools/* /usr/lib/linux-tools-*; do
		[ -d "${tools_dir}" ] || continue
		if [ -x "${tools_dir}/bpftool" ]; then
			sudo ln -sf "${tools_dir}/bpftool" /usr/local/bin/bpftool
			break
		fi
	done
fi

if ! command -v bpftool >/dev/null 2>&1 || ! bpftool version >/dev/null 2>&1; then
	echo "ERROR: bpftool is not available for kernel ${kernel}" >&2
	exit 1
fi

export CLANG="${clang_bpf}"
if [ -n "${GITHUB_ENV:-}" ]; then
	{
		echo "CLANG=${clang_bpf}"
		echo "CLANG_BPF=${clang_bpf}"
		echo "CGO_ENABLED=1"
		echo "LINUX_CGO=1"
	} >>"${GITHUB_ENV}"
fi

rm -f platform/linux/ebpf/vmlinux.h platform/linux/ebpf/edr.bpf.o
find platform/linux/ebpf -maxdepth 1 -name '*.o' -delete
bash scripts/gen_vmlinux.sh

if [ ! -s platform/linux/ebpf/vmlinux.h ]; then
	echo "ERROR: vmlinux.h was not generated" >&2
	exit 1
fi

vmlinux_lines="$(wc -l <platform/linux/ebpf/vmlinux.h | tr -d ' ')"
if [ "${vmlinux_lines}" -lt 500 ]; then
	echo "ERROR: vmlinux.h is too small (${vmlinux_lines} lines); expected BTF-generated header" >&2
	exit 1
fi
