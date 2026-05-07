//go:build windows

package forensics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectPrefetchWindowsSimulatedRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	pref := filepath.Join(root, "Prefetch")
	if err := os.MkdirAll(pref, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pref, "FOO-BAR.pf"), []byte("pfdata"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SystemRoot", root)
	cfg := &ForensicsDeepConfig{WorkDir: filepath.Join(t.TempDir(), "out"), MaxPrefetchFiles: 10}
	b := &DeepArtifactsBundle{}
	collectPrefetchWindows(cfg, b)
	if b.PrefetchError != "" {
		t.Fatal(b.PrefetchError)
	}
	if len(b.Prefetch) != 1 || !b.Prefetch[0].Copied {
		t.Fatalf("%+v", b.Prefetch)
	}
}
