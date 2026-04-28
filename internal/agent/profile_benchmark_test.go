package agent

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func BenchmarkNormalizePerformanceProfileLowResource(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cfg := config.Defaults()
		cfg.Performance.Profile = "low_resource"
		cfg.Performance.MaxMemoryMB = 1024
		normalizePerformanceProfile(&cfg)
	}
}

func BenchmarkNormalizePerformanceProfileStrict(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cfg := config.Defaults()
		cfg.Performance.Profile = "strict"
		cfg.Performance.MaxMemoryMB = 4096
		normalizePerformanceProfile(&cfg)
	}
}

func TestNormalizePerformanceProfileByMode(t *testing.T) {
	low := config.Defaults()
	low.Performance.Profile = "low_resource"
	low.Performance.MaxMemoryMB = 1024
	normalizePerformanceProfile(&low)
	if low.Performance.WorkerCount != 1 {
		t.Fatalf("low_resource worker_count=%d want 1", low.Performance.WorkerCount)
	}

	strict := config.Defaults()
	strict.Performance.Profile = "strict"
	normalizePerformanceProfile(&strict)
	if strict.Performance.WorkerCount < 2 {
		t.Fatalf("strict worker_count=%d want >=2", strict.Performance.WorkerCount)
	}
}
