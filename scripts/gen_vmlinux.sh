#!/usr/bin/env bash
set -euo pipefail

OUT="platform/linux/ebpf/vmlinux.h"
FALLBACK="platform/linux/ebpf/vmlinux_fallback.h"

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
