//go:build linux

package kernel

import "testing"

func TestDecodeDNSQName(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "simple A query (google.com)",
			raw:  []byte("\x06google\x03com\x00\x00\x01\x00\x01"),
			want: "google.com",
		},
		{
			name: "three-label name (www.google.com)",
			raw:  []byte("\x03www\x06google\x03com\x00\x00\x01\x00\x01"),
			want: "www.google.com",
		},
		{
			name: "compression pointer terminates early",
			raw:  []byte("\x03www\xC0\x0C"),
			want: "www",
		},
		{
			name: "empty input",
			raw:  nil,
			want: "",
		},
		{
			name: "root-only query",
			raw:  []byte("\x00\x00\x01\x00\x01"),
			want: "",
		},
		{
			name: "truncated label",
			raw:  []byte("\x08www"),
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := decodeDNSQName(c.raw)
			if got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestDecodeDNSQType(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "A record",
			raw:  []byte("\x06google\x03com\x00\x00\x01\x00\x01"),
			want: "A",
		},
		{
			name: "AAAA record",
			raw:  []byte("\x06google\x03com\x00\x00\x1c\x00\x01"),
			want: "AAAA",
		},
		{
			name: "TXT record",
			raw:  []byte("\x07example\x03com\x00\x00\x10\x00\x01"),
			want: "TXT",
		},
		{
			name: "MX record",
			raw:  []byte("\x07example\x03com\x00\x00\x0f\x00\x01"),
			want: "MX",
		},
		{
			name: "CNAME record",
			raw:  []byte("\x07example\x03com\x00\x00\x05\x00\x01"),
			want: "CNAME",
		},
		{
			name: "SRV record",
			raw:  []byte("\x04_sip\x04_tcp\x07example\x03com\x00\x00\x21\x00\x01"),
			want: "SRV",
		},
		{
			name: "unknown type",
			raw:  []byte("\x07example\x03com\x00\x12\x34\x00\x01"),
			want: "TYPE4660",
		},
		{
			name: "truncated qtype defaults to A",
			raw:  []byte("\x07example\x03com\x00"),
			want: "A",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := decodeDNSQType(c.raw)
			if got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}
