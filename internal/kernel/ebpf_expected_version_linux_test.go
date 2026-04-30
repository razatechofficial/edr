//go:build linux

package kernel

import "testing"

func TestEbpfExpectedObjectVersionNonEmpty(t *testing.T) {
	if v := ebpfExpectedObjectVersion(); v == "" {
		t.Fatal("embedded ebpf expected version is empty")
	}
}
