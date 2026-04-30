//go:build darwin

package collector

import "testing"

func TestParseDarwinLsofListen(t *testing.T) {
	sample := `COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
nginx     123 root    6u  IPv4 0xdead      0t0  TCP *:443 (LISTEN)
sshd      456 root    3u  IPv4 0xbeef      0t0  TCP *:22 (LISTEN)
`
	n, p := parseDarwinLsofListen(sample)
	if n != 2 || p != 2 {
		t.Fatalf("rows=%d pidHints=%d", n, p)
	}
}
