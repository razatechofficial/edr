package collector

import (
	"net"
	"testing"
)

func TestCommunityIDv1Stable(t *testing.T) {
	s := net.ParseIP("192.0.2.1")
	d := net.ParseIP("192.0.2.2")
	id1 := CommunityIDv1(6, s, d, 12345, 443)
	id2 := CommunityIDv1(6, d, s, 443, 12345)
	if id1 == "" || id2 == "" {
		t.Fatalf("empty id: %q %q", id1, id2)
	}
	if id1 != id2 {
		t.Fatalf("order sensitivity: %q vs %q", id1, id2)
	}
}
