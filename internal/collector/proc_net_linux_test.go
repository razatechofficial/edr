//go:build linux

package collector

import "testing"

func TestParseProcNetLineLocalPort(t *testing.T) {
	line := "   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 ffff8f8b2c3c0000 100 0 0 10 0"
	if p := parseProcNetLineLocalPort(line); p != 22 {
		t.Fatalf("port: got %d want 22", p)
	}
	if p := parseProcNetLineLocalPort("nope"); p != 0 {
		t.Fatalf("expected 0, got %d", p)
	}
}
