# Build eBPF programs for EDR agent
# Requires: clang >= 11, libbpf headers, kernel headers with BTF
#
# Usage:
#   make              – build all eBPF object files
#   make clean        – remove compiled objects
#   CLANG=/path/to/clang make  – use a specific clang binary

CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror

EBPF_SRC := $(wildcard ebpf/*.c)
EBPF_OBJ := $(EBPF_SRC:.c=.o)

.PHONY: all clean

all: $(EBPF_OBJ)

ebpf/%.o: ebpf/%.c ebpf/common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f ebpf/*.o
