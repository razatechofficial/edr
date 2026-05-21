package collector

import (
	"runtime"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestResolveFIMPathsStandardPreset(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Monitoring.FIMPreset = FIMPresetStandard
	paths := ResolveFIMPaths(cfg)
	if len(paths) == 0 {
		t.Fatal("expected paths")
	}
	switch runtime.GOOS {
	case "linux":
		if !containsPath(paths, "/etc") || !containsPath(paths, "/boot") {
			t.Fatalf("missing standard linux paths: %v", paths)
		}
	case "darwin":
		if !containsPath(paths, "/etc") || !containsPath(paths, "/Library/LaunchAgents") {
			t.Fatalf("missing standard darwin paths: %v", paths)
		}
	case "windows":
		if !containsPath(paths, `C:\Windows\System32`) {
			t.Fatalf("missing standard windows paths: %v", paths)
		}
	}
}

func TestResolveFIMPathsCustomOverride(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Monitoring.FIMPaths = []string{"/custom/path"}
	paths := ResolveFIMPaths(cfg)
	if len(paths) != 1 || paths[0] != "/custom/path" {
		t.Fatalf("got %v", paths)
	}
}

func TestShouldIgnoreFIMEvent(t *testing.T) {
	t.Parallel()
	pats := DefaultFIMIgnorePatterns()
	if !shouldIgnoreFIMEvent("/var/log/auth.log", pats) {
		t.Fatal("expected .log ignore")
	}
	if shouldIgnoreFIMEvent("/etc/passwd", pats) {
		t.Fatal("did not expect ignore")
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}
