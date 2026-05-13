#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# shellcheck source=scripts/ci/resolve_bpftool.sh
source "${ROOT}/scripts/ci/resolve_bpftool.sh"

find_clang_bpf() {
	for candidate in \
		"${CLANG:-}" \
		"/opt/homebrew/opt/llvm/bin/clang" \
		"/usr/local/opt/llvm/bin/clang" \
		"clang-17" "clang-16" "clang-15" "clang"; do
		[ -z "$candidate" ] && continue
		if command -v "$candidate" >/dev/null 2>&1; then
			if "$candidate" --target=bpf -print-targets 2>&1 | grep -q bpf; then
				echo "$candidate"
				return 0
			fi
		fi
	done
	echo ""
}

resolve_bpftool() {
	resolve_bpftool_for_btf_dump || resolve_bpftool_bin
}

validate_vmlinux_header() {
	local lines

	if [ ! -s "${OUT}" ]; then
		echo "ERROR: ${OUT} is missing or empty" >&2
		return 1
	fi

	lines="$(wc -l <"${OUT}" | tr -d ' ')"
	if [ "${lines}" -lt "${MIN_VMLINUX_LINES}" ]; then
		echo "ERROR: ${OUT} is too small (${lines} lines); expected a BTF-generated header" >&2
		return 1
	fi

	return 0
}

OUT="platform/linux/ebpf/vmlinux.h"
FALLBACK="platform/linux/ebpf/vmlinux_fallback.h"
VENDOR_BPF="platform/linux/ebpf/libbpf/bpf/bpf_helpers.h"
MIN_VMLINUX_LINES="${EDR_MIN_VMLINUX_LINES:-500}"

CLANG_BPF=$(find_clang_bpf)
if [ -z "$CLANG_BPF" ]; then
	echo "ERROR: No clang with BPF backend found." >&2
	echo "  macOS:  brew install llvm" >&2
	echo "  Ubuntu: apt-get install clang llvm" >&2
	exit 1
fi

if ! pkg-config --exists libbpf 2>/dev/null && [ ! -f "$VENDOR_BPF" ]; then
	echo "ERROR: libbpf headers not found." >&2
	echo "  Run: bash scripts/install_libbpf_headers.sh" >&2
	exit 1
fi

write_vmlinux_from_btf() {
	local bpftool_bin

	if [ ! -f /sys/kernel/btf/vmlinux ]; then
		return 1
	fi

	if ! bpftool_bin="$(resolve_bpftool)"; then
		return 1
	fi

	"${bpftool_bin}" btf dump file /sys/kernel/btf/vmlinux format c >"${OUT}"
}

write_vmlinux_fallback() {
	if [ ! -f "$FALLBACK" ]; then
		echo "ERROR: fallback vmlinux header missing: $FALLBACK" >&2
		return 1
	fi
	cp "$FALLBACK" "$OUT"
}

if [ -f "$OUT" ]; then
	echo "vmlinux.h already exists, skipping"
	exit 0
fi

if [ "${EDR_VMLINUX_FALLBACK:-0}" = "1" ]; then
	echo "Using fallback vmlinux.h (EDR_VMLINUX_FALLBACK=1)"
	write_vmlinux_fallback
	exit 0
fi

if write_vmlinux_from_btf; then
	echo "Generated vmlinux.h from running kernel BTF"
	validate_vmlinux_header
	exit 0
fi

if [ -n "${GITHUB_ACTIONS:-}" ]; then
	echo "ERROR: failed to generate vmlinux.h from kernel BTF on CI" >&2
	echo "  kernel: $(uname -r)" >&2
	echo "  btf:    $([ -f /sys/kernel/btf/vmlinux ] && echo present || echo missing)" >&2
	if resolve_bpftool >/dev/null 2>&1; then
		echo "  bpftool: $(resolve_bpftool)" >&2
	else
		echo "  bpftool: not found" >&2
	fi
	exit 1
fi

echo "Using fallback vmlinux.h (local dev without BTF)"
write_vmlinux_fallback
