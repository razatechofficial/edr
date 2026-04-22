CLANG      ?= clang
BPF_ARCH   := $(shell uname -m 2>/dev/null | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' || echo "x86")
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Wall -Werror
BPFTOOL    ?= bpftool
LIBBPF_SYSTEM := $(shell pkg-config --cflags libbpf 2>/dev/null)
VENDOR_INCLUDE := -I$(dir $(lastword $(MAKEFILE_LIST)))libbpf
INCLUDES = $(LIBBPF_SYSTEM) $(VENDOR_INCLUDE) -I/usr/include -I.

VMLINUX_H := vmlinux.h
VMLINUX_FALLBACK := vmlinux_fallback.h
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

.PHONY: all vmlinux

all: vmlinux $(OBJS)

vmlinux:
	@if [ -f "$(VMLINUX_H)" ]; then \
		echo "vmlinux.h exists"; \
	elif command -v $(BPFTOOL) >/dev/null 2>&1 && [ -f /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H); \
	else \
		cp $(VMLINUX_FALLBACK) $(VMLINUX_H); \
	fi

%.o: %.c common.h $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
