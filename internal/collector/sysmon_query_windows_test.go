//go:build windows

package collector

import (
	"strings"
	"testing"
)

func TestBuildSysmonXPathQuery_Network(t *testing.T) {
	q := buildSysmonXPathQuery(true)
	if len(q) < 20 {
		t.Fatalf("query too short: %q", q)
	}
	if !strings.Contains(q, "EventID=3") || !strings.Contains(q, "EventID=12") {
		t.Fatalf("expected EventID 3 and 12 in network-inclusive query: %s", q)
	}
	q2 := buildSysmonXPathQuery(false)
	if strings.Contains(q2, "EventID=3") {
		t.Fatalf("EventID 3 should be excluded without network events: %s", q2)
	}
	if strings.Contains(q2, "EventID=12") {
		t.Fatalf("EventID 12 should be excluded without network events: %s", q2)
	}
	if !strings.Contains(q2, "EventID=1") {
		t.Fatalf("EventID 1 should remain: %s", q2)
	}
}
