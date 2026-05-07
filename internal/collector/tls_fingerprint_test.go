package collector

import (
	"bytes"
	"testing"
)

func u24(n int) []byte {
	return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
}

func TestClientHelloFingerprints(t *testing.T) {
	var hello []byte
	hello = append(hello, 0x03, 0x03) // TLS 1.2
	hello = append(hello, bytes.Repeat([]byte{0}, 32)...)
	hello = append(hello, 0)                 // session id len
	hello = append(hello, 0, 2, 0x00, 0x2f)  // one cipher suite
	hello = append(hello, 1, 0)              // compression null
	hello = append(hello, 0, 0)              // extensions len 0

	hs := append([]byte{0x01}, u24(len(hello))...)
	hs = append(hs, hello...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs) & 0xff)}
	rec = append(rec, hs...)

	ja3, ja4 := ClientHelloFingerprints(rec)
	if ja3 == "" {
		t.Fatal("expected ja3")
	}
	if len(ja3) != 32 { // md5 hex
		t.Fatalf("ja3 len: %d", len(ja3))
	}
	if ja4 == "" {
		t.Fatal("expected ja4")
	}
}
