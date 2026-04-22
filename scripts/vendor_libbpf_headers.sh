#!/usr/bin/env bash
set -euo pipefail

LIBBPF_VERSION="1.3.0"
DEST="platform/linux/ebpf/libbpf/bpf"
BASE="https://raw.githubusercontent.com/libbpf/libbpf/v${LIBBPF_VERSION}/src"

mkdir -p "$DEST"
echo "Vendoring libbpf ${LIBBPF_VERSION} headers to ${DEST}..."

for f in bpf_helpers.h bpf_core_read.h bpf_tracing.h bpf_endian.h bpf_helper_defs.h; do
	echo "  fetching $f"
	curl -fsSL "${BASE}/${f}" -o "${DEST}/${f}"
done

echo "  fetching libbpf.h"
curl -fsSL "${BASE}/libbpf.h" -o "platform/linux/ebpf/libbpf/libbpf.h"
echo "Done. Commit platform/linux/ebpf/libbpf/ to your repository."
