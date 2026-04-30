package collector

import "testing"

func TestParseSsListenerStats_iprouteSample(t *testing.T) {
	// Typical iproute2 `ss -lntup` fragment (IPs shortened)
	sample := `
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      128    127.0.0.1:631      *:*    users:(("cupsd",pid=844,fd=7))
LISTEN 0      128    *:22               *:*    users:(("sshd",pid=1234,fd=3))
LISTEN 0      4096                   *:9000               *:*
`
	rows, hints := parseSsListenerStats(sample)
	if rows != 3 {
		t.Fatalf("listener rows=%d want 3", rows)
	}
	if hints != 2 {
		t.Fatalf("pid hints=%d want 2", hints)
	}
}

func TestParseSsListenerStats_fallbackHeader(t *testing.T) {
	sample := `
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp   LISTEN 0      128    0.0.0.0:443       0.0.0.0:*
`
	rows, hints := parseSsListenerStats(sample)
	if rows != 1 || hints != 0 {
		t.Fatalf("got rows=%d hints=%d", rows, hints)
	}
}

func TestParseSsListenerStats_noNetidColumn(t *testing.T) {
	sample := `State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      128    127.0.0.1:22       *:*    users:(("sshd",pid=1,fd=3))
`
	rows, hints := parseSsListenerStats(sample)
	if rows != 1 || hints != 1 {
		t.Fatalf("got rows=%d hints=%d", rows, hints)
	}
}
