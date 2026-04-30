#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXP_FILE="$ROOT/internal/kernel/ebpf_expected_version.txt"
MERGED="$ROOT/platform/linux/ebpf/edr.bpf.o"
SIDE="$ROOT/platform/linux/ebpf/edr.bpf.version"

if [[ ! -f "$EXP_FILE" ]]; then
	echo "bpf-version-check: missing $EXP_FILE" >&2
	exit 1
fi
expected="$(tr -d '\r\n' < "$EXP_FILE")"
if [[ -z "$expected" ]]; then
	echo "bpf-version-check: $EXP_FILE is empty" >&2
	exit 1
fi

if [[ ! -f "$MERGED" ]]; then
	echo "bpf-version-check: $MERGED not built — expected marker OK (${expected}); run make ebpf-link for full check"
	exit 0
fi

if [[ ! -f "$SIDE" ]]; then
	echo "bpf-version-check: $SIDE missing; run make ebpf-link (copies ebpf_expected_version.txt)" >&2
	exit 1
fi
actual="$(tr -d '\r\n' < "$SIDE")"
if [[ "$actual" != "$expected" ]]; then
	echo "bpf-version-check: mismatch edr.bpf.version='${actual}' ebpf_expected_version.txt='${expected}'" >&2
	exit 1
fi

echo "bpf-version-check: OK (${expected}, merged ${MERGED})"
