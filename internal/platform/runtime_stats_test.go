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
