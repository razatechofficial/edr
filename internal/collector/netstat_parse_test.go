package collector

import "testing"

func TestParseNetstatLine(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		dst  string
	}{
		{"tcp4       0      0  10.0.0.1.52341  1.2.3.4.443       ESTABLISHED", true, "1.2.3.4"},
		{"tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN", false, ""},
		{"tcp        0      0 192.168.1.5:22          192.168.1.10:54321      ESTABLISHED", true, "192.168.1.10"},
		{"udp        0      0 0.0.0.0:5353            0.0.0.0:*                           ", false, ""},
	}
	for _, tc := range cases {
		c, ok := parseNetstatLine(tc.line)
		if ok != tc.ok {
			t.Fatalf("line=%q ok=%v want %v got %+v", tc.line, ok, tc.ok, c)
		}
		if !tc.ok {
			continue
		}
		if c.dstIP != tc.dst {
			t.Fatalf("dstIP=%q want %q line=%q", c.dstIP, tc.dst, tc.line)
		}
	}
}
