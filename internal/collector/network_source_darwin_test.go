//go:build darwin

package collector

import "testing"

func TestSplitLsofHostPort_V4(t *testing.T) {
	host, port, ok := splitLsofHostPort("192.168.1.1:80")
	if !ok || host != "192.168.1.1" || port != 80 {
		t.Fatalf("got host=%q port=%d ok=%v", host, port, ok)
	}
}

func TestSplitLsofHostPort_V6(t *testing.T) {
	host, port, ok := splitLsofHostPort("[2001:db8::1]:443")
	if !ok || host != "2001:db8::1" || port != 443 {
		t.Fatalf("got host=%q port=%d ok=%v", host, port, ok)
	}
}

func TestSplitLsofHostPort_Wildcard(t *testing.T) {
	host, port, ok := splitLsofHostPort("*:8080")
	if !ok || host != "" || port != 8080 {
		t.Fatalf("got host=%q port=%d ok=%v", host, port, ok)
	}
}

func TestParseLsofConn_Established(t *testing.T) {
	s, sp, d, dp, ok := parseLsofConn("10.0.0.1:55555->1.2.3.4:443")
	if !ok || s != "10.0.0.1" || sp != 55555 || d != "1.2.3.4" || dp != 443 {
		t.Fatalf("got s=%q:%d d=%q:%d ok=%v", s, sp, d, dp, ok)
	}
}

func TestParseLsofConn_Listening(t *testing.T) {
	s, sp, d, dp, ok := parseLsofConn("*:80")
	if !ok || sp != 80 || d != "" || dp != 0 {
		t.Fatalf("got s=%q:%d d=%q:%d ok=%v", s, sp, d, dp, ok)
	}
}
