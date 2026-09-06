package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRuntimeStatsEvents(t *testing.T) {
	dir := t.TempDir()
	if got := ReadRuntimeStatsEvents(dir); got != 0 {
		t.Fatalf("missing file = %d", got)
	}
	path := filepath.Join(dir, runtimeStatsName)
	if err := os.WriteFile(path, []byte(`{"events_processed": 18400}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ReadRuntimeStatsEvents(dir); got != 18400 {
		t.Fatalf("got %d", got)
	}
}

func TestReadRuntimeStatsResources(t *testing.T) {
	dir := t.TempDir()
	if _, _, ok := ReadRuntimeStatsResources(dir); ok {
		t.Fatal("missing file must not look like live stats")
	}
	path := filepath.Join(dir, runtimeStatsName)
	if err := os.WriteFile(path, []byte(`{"cpu_percent": 4.2, "memory_mb": 135}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cpu, mem, ok := ReadRuntimeStatsResources(dir)
	if !ok || cpu != 4.2 || mem != 135 {
		t.Fatalf("cpu=%v mem=%v ok=%v", cpu, mem, ok)
	}
}
