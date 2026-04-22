#!/usr/bin/env bash
set -euo pipefail

OUT="platform/linux/ebpf/vmlinux.h"
FALLBACK="platform/linux/ebpf/vmlinux_fallback.h"
VENDOR_BPF="platform/linux/ebpf/libbpf/bpf/bpf_helpers.h"

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

CLANG_BPF=$(find_clang_bpf)
if [ -z "$CLANG_BPF" ]; then
	echo "ERROR: No clang with BPF backend found." >&2
	echo "  macOS:  brew install llvm" >&2
	echo "  Ubuntu: apt-get install clang llvm" >&2
	exit 1
fi

if ! pkg-config --exists libbpf 2>/dev/null && [ ! -f "$VENDOR_BPF" ]; then
	echo "ERROR: libbpf headers not found." >&2
	echo "  Run: bash scripts/vendor_libbpf_headers.sh" >&2
	exit 1
fi

if [ -f "$OUT" ]; then
	echo "vmlinux.h already exists, skipping"
	exit 0
fi

if command -v bpftool >/dev/null 2>&1 && [ -f /sys/kernel/btf/vmlinux ]; then
	echo "Generating vmlinux.h from running kernel BTF..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUT"
elif [ -f "$FALLBACK" ]; then
	echo "Using fallback vmlinux.h (CI mode)"
	cp "$FALLBACK" "$OUT"
else
	echo "ERROR: cannot generate vmlinux.h" >&2
	exit 1
fi
