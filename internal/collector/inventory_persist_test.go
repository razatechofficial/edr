package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistInventorySnapshot_roundTrip(t *testing.T) {
	dir := t.TempDir()
	m := map[string]any{"a": float64(1), "b": "x"}
	h1, ch1, p1, err := persistInventorySnapshot(dir, m)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == "" || !ch1 || p1 == "" {
		t.Fatalf("first write: h=%q ch=%v p=%q", h1, ch1, p1)
	}
	if _, err := os.Stat(filepath.Join(dir, inventorySnapshotFile)); err != nil {
		t.Fatal(err)
	}
	h2, ch2, p2, err := persistInventorySnapshot(dir, m)
	if err != nil {
		t.Fatal(err)
	}
	if h2 != h1 || ch2 || p2 != p1 {
		t.Fatalf("unchanged payload should not report changed: h1=%s h2=%s ch2=%v", h1, h2, ch2)
	}
	m["a"] = float64(2)
	h3, ch3, _, err := persistInventorySnapshot(dir, m)
	if err != nil {
		t.Fatal(err)
	}
	if h3 == h1 || !ch3 {
		t.Fatalf("expect change after edit h1=%s h3=%s ch3=%v", h1, h3, ch3)
	}
}
