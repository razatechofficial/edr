#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

sudo apt-get update -qq
sudo apt-get install -y clang-16 llvm-16 libbpf-dev libyara-dev pkg-config bpftool \
	linux-headers-"$(uname -r)" \
	linux-tools-"$(uname -r)" linux-tools-generic \
	|| sudo apt-get install -y clang llvm libbpf-dev libyara-dev pkg-config bpftool

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

export CLANG="${clang_bpf}"
if [ -n "${GITHUB_ENV:-}" ]; then
	{
		echo "CLANG=${clang_bpf}"
		echo "CGO_ENABLED=1"
		echo "LINUX_CGO=1"
	} >>"${GITHUB_ENV}"
fi

rm -f platform/linux/ebpf/vmlinux.h platform/linux/ebpf/edr.bpf.o
find platform/linux/ebpf -maxdepth 1 -name '*.o' -delete
bash scripts/gen_vmlinux.sh
