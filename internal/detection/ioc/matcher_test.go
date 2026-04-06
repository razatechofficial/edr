package ioc

import (
	"testing"

	"go.uber.org/zap"
)

func newTestMatcher(t *testing.T) *Matcher {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return NewMatcher(logger)
}

func TestMatcherCheckHash(t *testing.T) {
	t.Parallel()
	m := newTestMatcher(t)
	m.Hashes().Add(HashEntry{
		Hash:          "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadba",
		Type:          HashSHA256,
		MalwareFamily: "TestMalware",
		Severity:      "critical",
	})

	result := m.CheckHash("badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadba")
	if !result.Matched {
		t.Fatal("CheckHash returned Matched=false, want true")
	}
	if result.Type != "hash" {
		t.Errorf("Type = %q, want %q", result.Type, "hash")
	}
}

func TestMatcherCheckIP(t *testing.T) {
	t.Parallel()
	m := newTestMatcher(t)
	m.IPs().Add(IPEntry{Address: "203.0.113.66", Severity: "high"})

	result := m.CheckIP("203.0.113.66")
	if !result.Matched {
		t.Fatal("CheckIP returned Matched=false, want true")
	}
	if result.Type != "ip" {
		t.Errorf("Type = %q, want %q", result.Type, "ip")
	}
}

func TestMatcherCheckDomain(t *testing.T) {
	t.Parallel()
	m := newTestMatcher(t)
	m.Domains().Add(DomainEntry{Domain: "c2.evil.com", Severity: "critical"})

	result := m.CheckDomain("c2.evil.com")
	if !result.Matched {
		t.Fatal("CheckDomain returned Matched=false, want true")
	}
	if result.Type != "domain" {
		t.Errorf("Type = %q, want %q", result.Type, "domain")
	}
}

func TestMatcherNoMatch(t *testing.T) {
	t.Parallel()
	m := newTestMatcher(t)

	if m.CheckHash("clean").Matched {
		t.Error("CheckHash matched a clean hash")
	}
	if m.CheckIP("127.0.0.1").Matched {
		t.Error("CheckIP matched a clean IP")
	}
	if m.CheckDomain("google.com").Matched {
		t.Error("CheckDomain matched a clean domain")
	}
}

func TestMatcherStats(t *testing.T) {
	t.Parallel()
	m := newTestMatcher(t)
	m.Hashes().Add(HashEntry{Hash: "abc", Type: HashSHA256})
	m.IPs().Add(IPEntry{Address: "1.2.3.4"})
	m.Domains().Add(DomainEntry{Domain: "bad.com"})

	m.CheckHash("abc")
	m.CheckHash("xyz")
	m.CheckIP("1.2.3.4")
	m.CheckDomain("bad.com")
	m.CheckDomain("good.com")

	stats := m.Stats()
	if stats.HashLookups != 2 {
		t.Errorf("HashLookups = %d, want 2", stats.HashLookups)
	}
	if stats.HashMatches != 1 {
		t.Errorf("HashMatches = %d, want 1", stats.HashMatches)
	}
	if stats.IPLookups != 1 {
		t.Errorf("IPLookups = %d, want 1", stats.IPLookups)
	}
	if stats.IPMatches != 1 {
		t.Errorf("IPMatches = %d, want 1", stats.IPMatches)
	}
	if stats.DomainLookups != 2 {
		t.Errorf("DomainLookups = %d, want 2", stats.DomainLookups)
	}
	if stats.DomainMatches != 1 {
		t.Errorf("DomainMatches = %d, want 1", stats.DomainMatches)
	}
}
