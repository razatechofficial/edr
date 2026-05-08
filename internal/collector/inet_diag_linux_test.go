//go:build linux

package collector

import "testing"

func TestDecodeProcNetAddr(t *testing.T) {
	ip, port, ok := decodeProcNetAddr("0100007F:A1B2")
	if !ok || ip != "127.0.0.1" || port != 0xa1b2 {
		t.Fatalf("got ip=%q port=%d ok=%v", ip, port, ok)
	}
	if _, _, ok2 := decodeProcNetAddr("bad"); ok2 {
		t.Fatal("expected false")
	}
}

func TestTCPQuintKey(t *testing.T) {
	k := tcpQuintKey("10.0.0.1", 443, "192.168.0.5", 54321)
	if k != "10.0.0.1|443-192.168.0.5|54321-tcp" {
		t.Fatalf("got %q", k)
	}
}

func TestParseHexUint16(t *testing.T) {
	v, err := parseHexUint16("00FF")
	if err != nil || v != 255 {
		t.Fatalf("v=%d err=%v", v, err)
	}
	if _, err := parseHexUint16("ff"); err == nil {
		t.Fatal("expected error for short hex")
	}
}
