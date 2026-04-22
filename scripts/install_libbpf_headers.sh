#!/usr/bin/env bash
set -euo pipefail

LIBBPF_VERSION="1.3.0"
LIBBPF_URL="https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz"
DEST="platform/linux/ebpf/libbpf/bpf"

mkdir -p "$DEST"
echo "Installing libbpf headers v${LIBBPF_VERSION} into ${DEST}..."

curl -L "$LIBBPF_URL" | tar -xz --strip=2 \
	-C "$DEST" \
	"libbpf-${LIBBPF_VERSION}/src/bpf_helpers.h" \
	"libbpf-${LIBBPF_VERSION}/src/bpf_core_read.h" \
	"libbpf-${LIBBPF_VERSION}/src/bpf_tracing.h" \
	"libbpf-${LIBBPF_VERSION}/src/bpf_endian.h" \
	"libbpf-${LIBBPF_VERSION}/src/bpf_helper_defs.h"

curl -fsSL "https://raw.githubusercontent.com/libbpf/libbpf/v${LIBBPF_VERSION}/src/libbpf.h" \
	-o "platform/linux/ebpf/libbpf/libbpf.h"

echo "libbpf headers installed."
