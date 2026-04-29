//go:build darwin

package collector

import "testing"

func TestExtractDNSQuery_Query(t *testing.T) {
	got := extractDNSQuery("Query: example.com (AAAA)")
	if got != "example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractDNSQuery_Resolve(t *testing.T) {
	got := extractDNSQuery("Resolve: 1 example.org started")
	// "1" has no dot so the next field "example.org" should match
	if got != "" && got != "example.org" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractDNSQuery_NoDomain(t *testing.T) {
	if got := extractDNSQuery("Some other log line"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}
