package collectors

import (
	"testing"

	"go.uber.org/zap"
)

func TestNetworkCollectorName(t *testing.T) {
	t.Parallel()
	c := NewNetworkCollector(zap.NewNop())
	if got := c.Name(); got != "network" {
		t.Errorf("Name() = %q, want %q", got, "network")
	}
}

func TestIPv4Format(t *testing.T) {
	t.Parallel()
	payload := []byte{192, 168, 1, 1}
	r := newPayloadReader(payload)
	addr := readAddr(r, afINET)
	if addr != "192.168.1.1" {
		t.Errorf("IPv4 addr = %q, want %q", addr, "192.168.1.1")
	}
	if r.Err() != nil {
		t.Errorf("unexpected error: %v", r.Err())
	}
}

func TestIPv6Format(t *testing.T) {
	t.Parallel()
	payload := make([]byte, 16)
	payload[15] = 1 // ::1
	r := newPayloadReader(payload)
	addr := readAddr(r, afINET6)
	if addr != "::1" {
		t.Errorf("IPv6 addr = %q, want %q", addr, "::1")
	}
	if r.Err() != nil {
		t.Errorf("unexpected error: %v", r.Err())
	}
}
