//go:build linux

package collector

import (
	"net"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIPv4ListenPortBusy_WithListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		t.Fatalf("port: %q err=%v", portStr, err)
	}
	if !ipv4ListenPortBusy(unix.IPPROTO_TCP, port) {
		t.Fatal("expected EADDRINUSE=true for bound TCP port")
	}
}
