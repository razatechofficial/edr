package ioc

import "testing"

func TestIPDBExactMatch(t *testing.T) {
	t.Parallel()
	db := NewIPDB()
	db.Add(IPEntry{Address: "192.168.1.100", Severity: "high"})

	entry, found := db.Lookup("192.168.1.100")
	if !found {
		t.Fatal("Lookup returned false for exact IP")
	}
	if entry.Severity != "high" {
		t.Errorf("Severity = %q, want %q", entry.Severity, "high")
	}
}

func TestIPDBCIDRMatch(t *testing.T) {
	t.Parallel()
	db := NewIPDB()
	db.Add(IPEntry{Address: "10.0.0.0", CIDR: "10.0.0.0/8", Severity: "medium"})

	entry, found := db.Lookup("10.1.2.3")
	if !found {
		t.Fatal("Lookup returned false for IP in CIDR range 10.0.0.0/8")
	}
	if entry.Severity != "medium" {
		t.Errorf("Severity = %q, want %q", entry.Severity, "medium")
	}
}

func TestIPDBNoMatch(t *testing.T) {
	t.Parallel()
	db := NewIPDB()
	db.Add(IPEntry{Address: "192.168.1.1"})

	_, found := db.Lookup("8.8.8.8")
	if found {
		t.Error("Lookup returned true for non-matching IP")
	}
}

func TestIPDBIPv6(t *testing.T) {
	t.Parallel()
	db := NewIPDB()
	db.Add(IPEntry{Address: "2001:db8::1", Severity: "critical"})

	entry, found := db.Lookup("2001:db8::1")
	if !found {
		t.Fatal("Lookup returned false for exact IPv6 address")
	}
	if entry.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", entry.Severity, "critical")
	}
}

func TestIPDBCIDRv6(t *testing.T) {
	t.Parallel()
	db := NewIPDB()
	db.Add(IPEntry{Address: "2001:db8::", CIDR: "2001:db8::/32", Severity: "high"})

	entry, found := db.Lookup("2001:db8::abcd:1234")
	if !found {
		t.Fatal("Lookup returned false for IPv6 in CIDR /32")
	}
	if entry.Severity != "high" {
		t.Errorf("Severity = %q, want %q", entry.Severity, "high")
	}
}
