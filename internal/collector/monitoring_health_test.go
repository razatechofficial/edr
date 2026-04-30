package collector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

type fakeHealthyCollector struct {
	name string
	snap map[string]any
}

func (f *fakeHealthyCollector) Name() string                                { return f.name }
func (f *fakeHealthyCollector) Collect(ctx context.Context) ([]Telemetry, error) { return nil, nil }
func (f *fakeHealthyCollector) ExportMonitoringHealth() map[string]any {
	return f.snap
}

func TestMonitoringSource_ToMapStableShape(t *testing.T) {
	src := MonitoringSource{
		Name:          "process",
		OS:            runtime.GOOS,
		Source:        "ebpf",
		Status:        "healthy",
		EPSIn:         12,
		EPSOut:        10,
		Dropped:       2,
		QueueDepth:    4,
		LastEventUnix: 1700000000,
	}
	m := src.ToMap()
	required := []string{"name", "os", "source", "status", "eps_in", "eps_out", "dropped", "queue_depth", "last_event_unix"}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			t.Errorf("MonitoringSource.ToMap missing key %q", k)
		}
	}
	if _, ok := m["last_error"]; ok {
		t.Error("empty last_error must be omitted")
	}
}

func TestWriteMonitoringHealth_AggregatesSources(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Agent.DataDir = dir
	cols := []Collector{
		&fakeHealthyCollector{name: "process", snap: MonitoringSource{Name: "process", Source: "ebpf", Status: "healthy"}.ToMap()},
		&fakeHealthyCollector{name: "file", snap: MonitoringSource{Name: "file", Source: "fsnotify", Status: "degraded", LastError: "boom"}.ToMap()},
		&fakeHealthyCollector{name: "kernel", snap: KernelHealthMap("fake", map[string]any{"n": 1}, map[string]any{"d": 2}, nil)},
	}
	WriteMonitoringHealth(cfg, cols, nil)

	b, err := os.ReadFile(filepath.Join(dir, "monitoring_health.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	srcs, ok := got["sources"].([]any)
	if !ok || len(srcs) != 3 {
		t.Fatalf("sources not aggregated: %v", got["sources"])
	}
	if _, ok := got["runtime"]; !ok {
		t.Fatal("runtime snapshot missing")
	}
	if _, ok := got["kernel"]; !ok {
		t.Fatal("legacy kernel key missing")
	}
}
