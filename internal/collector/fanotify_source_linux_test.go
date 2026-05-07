//go:build linux

package collector

import "testing"

func Test_readMountinfoFingerprint_nonEmpty(t *testing.T) {
	fp, err := readMountinfoFingerprint()
	if err != nil {
		t.Skip(err)
	}
	if len(fp) != 64 {
		t.Fatalf("expected sha256 hex len 64, got %d", len(fp))
	}
}

func TestFanotifySource_ExportMonitoringHealth_NotStarted(t *testing.T) {
	t.Parallel()
	f := NewFanotifySource("ep", "h", nil, []string{"/"}, nil)
	m := f.ExportMonitoringHealth()
	if m["status"] != "unavailable" {
		t.Fatalf("status: %v", m["status"])
	}
}
