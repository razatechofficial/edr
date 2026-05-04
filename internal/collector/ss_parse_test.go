package collector

import "testing"

func TestParseSSLine(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		dst  string
	}{
		{"tcp   ESTAB  0  0  127.0.0.1:22  10.0.0.2:443", true, "10.0.0.2"},
		{"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port", false, ""},
		{"udp   ESTAB  0  0  192.168.0.1:53  8.8.8.8:12345", true, "8.8.8.8"},
	}
	for _, tc := range cases {
		c, ok := parseSSLine(tc.line)
		if ok != tc.ok {
			t.Fatalf("line=%q ok=%v want=%v", tc.line, ok, tc.ok)
		}
		if !tc.ok {
			continue
		}
		if c.dstIP != tc.dst {
			t.Fatalf("line=%q dstIP=%q want %q", tc.line, c.dstIP, tc.dst)
		}
	}
}
