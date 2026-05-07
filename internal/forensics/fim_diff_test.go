package forensics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFIMDiffCacheEmitsOnSecondWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "watched.txt")
	if err := os.WriteFile(p, []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewFIMDiffCache(FIMDiffConfig{
		Enabled:      true,
		MaxFileBytes: 4096,
		PathGlobs:    []string{p},
	})
	if c == nil {
		t.Fatal("expected cache")
	}
	if _, err := c.DiffOnModify(p, func() ([]byte, error) { return os.ReadFile(p) }); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b64, err := c.DiffOnModify(p, func() ([]byte, error) { return os.ReadFile(p) })
	if err != nil {
		t.Fatal(err)
	}
	if b64 == "" {
		t.Fatal("expected diff payload")
	}
	if c.EmitsTotal() != 1 {
		t.Fatalf("emits: %d", c.EmitsTotal())
	}
}
