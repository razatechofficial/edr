package main

import (
	"testing"

	"github.com/razatechofficial/edr/internal/xdrclient"
)

func TestEnrollmentHostFromDomain(t *testing.T) {
	if got := enrollmentHostFromDomain(""); got != xdrclient.DefaultEnrollmentHost {
		t.Fatalf("blank = %q", got)
	}
	if got := enrollmentHostFromDomain("xdr.averox.com"); got != "enroll.xdr.averox.com:443" {
		t.Fatalf("saas apex = %q", got)
	}
	if got := enrollmentHostFromDomain("xdr.corp.example"); got != "enroll.xdr.corp.example:443" {
		t.Fatalf("on-prem apex = %q", got)
	}
	if got := enrollmentHostFromDomain("enroll.xdr.averox.com:443"); got != "enroll.xdr.averox.com:443" {
		t.Fatalf("already mapped = %q", got)
	}
}

func TestDomainLooksInvalid(t *testing.T) {
	if domainLooksInvalid("") {
		t.Fatal("blank is allowed")
	}
	if domainLooksInvalid("xdr.averox.com") {
		t.Fatal("apex should pass")
	}
	for _, bad := range []string{"https://xdr.averox.com", "ingest.xdr.averox.com", "localhost", "enroll.xdr.averox.com", "xdr.averox.com:443"} {
		if !domainLooksInvalid(bad) {
			t.Fatalf("expected invalid: %q", bad)
		}
	}
}
