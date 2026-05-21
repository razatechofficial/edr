package collector

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestResolveFIMPathsStandardPreset(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Monitoring.FIMPreset = FIMPresetStandard
	paths := ResolveFIMPaths(cfg)
	if len(paths) == 0 {
		t.Fatal("expected standard preset paths")
	}
	switch {
	case len(paths) >= 3:
	default:
		t.Fatalf("unexpected path count: %d", len(paths))
	}
}

