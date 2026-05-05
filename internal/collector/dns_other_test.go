//go:build !linux && !darwin && !windows

package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProbeRareDNSSource_PicksReadablePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dns.log")
	if err := os.WriteFile(p, []byte("query[A] example.org"), 0o644); err != nil {
		t.Fatal(err)
	}
	gotPath, probes, winner := probeRareDNSSource([]string{"", p})
	if gotPath != p {
		t.Fatalf("path=%q want %q", gotPath, p)
	}
	if winner != "syslog_tail" {
		t.Fatalf("winner=%q", winner)
	}
	if len(probes) == 0 {
		t.Fatal("expected probe trace")
	}
}
