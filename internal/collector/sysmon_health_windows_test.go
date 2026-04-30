//go:build windows

package collector

import "testing"

func TestSysmonExportMonitoringHealth_NetworkDedupNote(t *testing.T) {
	s := NewSysmonSource("ep", "h", t.TempDir(), true)
	m := s.ExportMonitoringHealth()
	n, _ := m["notes"].(string)
	if n == "" {
		t.Fatal("expected dedup guidance in notes when network EIDs subscribed")
	}
	s2 := NewSysmonSource("ep", "h", t.TempDir(), false)
	m2 := s2.ExportMonitoringHealth()
	if _, ok := m2["notes"]; ok {
		t.Fatal("unexpected notes when network EIDs omitted from xpath")
	}
}
