package collector

import "testing"

func TestParseLsofInetLine(t *testing.T) {
	line := `sshd    1234 root    3u  IPv4 0x1234      0t0  TCP 127.0.0.1:22->93.184.216.34:443 (ESTABLISHED)`
	c, ok := parseLsofInetLine(line)
	if !ok {
		t.Fatal("expected ok")
	}
	if c.proto != "tcp" || c.dstIP != "93.184.216.34" || c.dstPort != 443 {
		t.Fatalf("%+v", c)
	}
	if _, ok := parseLsofInetLine("node  1 u  IPv4  TCP *:22 (LISTEN)"); ok {
		t.Fatal("LISTEN without peer should not parse")
	}
}
