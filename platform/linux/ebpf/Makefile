CLANG      ?= clang
define find_clang
$(shell \
  if [ -n "$(CLANG)" ] && $(CLANG) --target=bpf -print-targets 2>&1 | grep -q bpf; then \
    echo "$(CLANG)"; \
  elif [ -x "/opt/homebrew/opt/llvm/bin/clang" ] && \
       /opt/homebrew/opt/llvm/bin/clang --target=bpf -print-targets 2>&1 | grep -q bpf; then \
    echo "/opt/homebrew/opt/llvm/bin/clang"; \
  elif [ -x "/usr/local/opt/llvm/bin/clang" ] && \
       /usr/local/opt/llvm/bin/clang --target=bpf -print-targets 2>&1 | grep -q bpf; then \
    echo "/usr/local/opt/llvm/bin/clang"; \
  elif command -v clang-17 >/dev/null 2>&1; then \
    echo "clang-17"; \
  elif command -v clang-16 >/dev/null 2>&1; then \
    echo "clang-16"; \
  elif command -v clang >/dev/null 2>&1 && \
       clang --target=bpf -print-targets 2>&1 | grep -q bpf; then \
    echo "clang"; \
  else \
    echo ""; \
  fi)
endef
CLANG_BPF := $(call find_clang)
ifeq ($(CLANG_BPF),)
$(error No clang with BPF backend found. On macOS: brew install llvm; On Ubuntu: apt-get install clang llvm; Or set CLANG=/path/to/bpf-capable-clang)
endif
BPF_ARCH   := $(shell uname -m 2>/dev/null | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' || echo "x86")
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Wall -Werror -Wno-missing-declarations
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
	$(CLANG_BPF) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
