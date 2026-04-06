package ioc

import "testing"

func TestDomainDBExactMatch(t *testing.T) {
	t.Parallel()
	db := NewDomainDB()
	db.Add(DomainEntry{Domain: "evil.com", Severity: "high"})

	entry, found := db.Lookup("evil.com")
	if !found {
		t.Fatal("Lookup returned false for exact domain")
	}
	if entry.Severity != "high" {
		t.Errorf("Severity = %q, want %q", entry.Severity, "high")
	}
}

func TestDomainDBWildcardMatch(t *testing.T) {
	t.Parallel()
	db := NewDomainDB()
	db.Add(DomainEntry{Domain: "*.evil.com", IsWildcard: true, Severity: "critical"})

	entry, found := db.Lookup("sub.evil.com")
	if !found {
		t.Fatal("Lookup returned false for subdomain matching *.evil.com")
	}
	if entry.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", entry.Severity, "critical")
	}
}

func TestDomainDBWildcardNoMatchBase(t *testing.T) {
	t.Parallel()
	db := NewDomainDB()
	db.Add(DomainEntry{Domain: "*.evil.com", IsWildcard: true})

	_, found := db.Lookup("evil.com")
	if found {
		t.Error("wildcard *.evil.com should NOT match the bare domain evil.com")
	}
}

func TestDomainDBNoMatch(t *testing.T) {
	t.Parallel()
	db := NewDomainDB()
	db.Add(DomainEntry{Domain: "evil.com"})

	_, found := db.Lookup("safe.org")
	if found {
		t.Error("Lookup returned true for non-malicious domain")
	}
}

func TestDomainDBDeepSubdomain(t *testing.T) {
	t.Parallel()
	db := NewDomainDB()
	db.Add(DomainEntry{Domain: "*.evil.com", IsWildcard: true})

	_, found := db.Lookup("a.b.c.evil.com")
	if !found {
		t.Error("Lookup returned false; *.evil.com should match a.b.c.evil.com")
	}
}
