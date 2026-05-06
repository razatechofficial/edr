//go:build linux

package collector

import (
	"testing"
)

func TestFanotifySource_ExportMonitoringHealth_NotStarted(t *testing.T) {
	t.Parallel()
	f := NewFanotifySource("ep", "h", nil, []string{"/"}, nil)
	m := f.ExportMonitoringHealth()
	if m["status"] != "unavailable" {
		t.Fatalf("status: %v", m["status"])
	}
}
