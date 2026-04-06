package collectors

import (
	"testing"

	"go.uber.org/zap"
)

func TestDNSCollectorName(t *testing.T) {
	t.Parallel()
	c := NewDNSCollector(zap.NewNop())
	if got := c.Name(); got != "dns" {
		t.Errorf("Name() = %q, want %q", got, "dns")
	}
}

func TestQueryTypeMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		typeNum uint16
		want    string
	}{
		{1, "A"},
		{2, "NS"},
		{5, "CNAME"},
		{6, "SOA"},
		{12, "PTR"},
		{15, "MX"},
		{16, "TXT"},
		{28, "AAAA"},
		{33, "SRV"},
		{255, "ANY"},
		{99, "TYPE99"},
	}

	for _, tc := range tests {
		got := dnsTypeName(tc.typeNum)
		if got != tc.want {
			t.Errorf("dnsTypeName(%d) = %q, want %q", tc.typeNum, got, tc.want)
		}
	}
}
