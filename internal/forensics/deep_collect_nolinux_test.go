package forensics

import (
	"path/filepath"
	"runtime"
	"testing"

	"go.uber.org/zap"
)

func TestCollectDeepToWorkdir_NoOpWhenFlagsOff(t *testing.T) {
	t.Parallel()
	out := t.TempDir()
	got := CollectDeepToWorkdir(out, ForensicsDeepConfig{})
	if len(got) != 0 {
		t.Fatalf("expected no records, got %d", len(got))
	}
}

func TestForensicsDeepConfigAnyEnabled(t *testing.T) {
	t.Parallel()
	if (ForensicsDeepConfig{}).AnyEnabled() {
		t.Fatal("expected false")
	}
	cfg := ForensicsDeepConfig{WindowsPrefetchEnabled: true}
	if !cfg.AnyEnabled() {
		t.Fatal("expected true")
	}
}

func TestCollectDeepArtifactsLinuxNoPanic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only smoke")
	}
	ac := NewArtifactCollector(zap.NewNop(), nil)
	sa := &SystemArtifacts{}
	ac.collectDeepArtifacts(t.Context(), sa, ForensicsDeepConfig{
		WindowsPrefetchEnabled: true,
		WorkDir:                filepath.Join(t.TempDir(), "d"),
	})
	if sa.Deep != nil {
		t.Fatalf("expected no deep bundle on linux with windows-only flags, got %+v", sa.Deep)
	}
}
