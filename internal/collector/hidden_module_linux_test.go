//go:build linux

package collector

import (
	"strings"
	"testing"
)

func TestReadProcModuleNamesFromReader(t *testing.T) {
	in := "bridge 20480 0 - Live 0xffffffffc0a7b000\nnf_conntrack 163840 0 - Live 0xffffffffc08b2000\n"
	m, err := readProcModuleNamesFromReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if !m["bridge"] || !m["nf_conntrack"] {
		t.Fatalf("unexpected map: %+v", m)
	}
}
