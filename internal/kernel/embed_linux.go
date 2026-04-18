//go:build linux && embed_ebpf

package kernel

import _ "embed"

//go:embed bpf/edr.bpf.o
var bpfBytecodeEmbed []byte

func init() {
	bpfBytecode = bpfBytecodeEmbed
}
