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

func (f *fakeHealthyCollector) Name() string                                     { return f.name }
func (f *fakeHealthyCollector) Collect(ctx context.Context) ([]Telemetry, error) { return nil, nil }
func (f *fakeHealthyCollector) ExportMonitoringHealth() map[string]any {
	return f.snap
}

func TestMonitoringHealthSchemaVersion_Current(t *testing.T) {
	if MonitoringHealthSchemaVersion != 2 {
		t.Fatalf("update golden fixtures under cmd/agent/testdata/monitoring_health when bumping schema (got %d)", MonitoringHealthSchemaVersion)
	}
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

func TestWriteMonitoringHealth_SyntheticKernelWhenTierNoCollector(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Agent.DataDir = dir
	cfg.Monitoring.Mode = "auto"
	cfg.Monitoring.KernelEnabled = true
	cols := []Collector{
		&fakeHealthyCollector{name: "process", snap: MonitoringSource{Name: "process", Source: "stub", Status: "healthy"}.ToMap()},
	}
	WriteMonitoringHealth(cfg, cols, nil)
	b, err := os.ReadFile(filepath.Join(dir, "monitoring_health.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	if err := json.Unmarshal(b, &snap); err != nil {
		t.Fatal(err)
	}
	srcs, _ := snap["sources"].([]any)
	var kernelRow map[string]any
	for _, raw := range srcs {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if m["name"] == "kernel" {
			kernelRow = m
			break
		}
	}
	if kernelRow == nil {
		t.Fatal("expected synthetic kernel row")
	}
	if kernelRow["status"] != "absent" {
		t.Fatalf("kernel status=%v want absent", kernelRow["status"])
	}
}

func TestCollapseMonitoringSourcesByName_PrefersHealthierStatus(t *testing.T) {
	in := []map[string]any{
		MonitoringSource{Name: "dns", Source: "none", Status: "unavailable"}.ToMap(),
		MonitoringSource{Name: "dns", Source: "journal_systemd_dns", Status: "healthy"}.ToMap(),
	}
	got := collapseMonitoringSourcesByName(in)
	if len(got) != 1 {
		t.Fatalf("len=%d want 1", len(got))
	}
	name, _ := got[0]["name"].(string)
	if name != "dns" {
		t.Fatalf("name=%q", name)
	}
	status, _ := got[0]["status"].(string)
	if status != "healthy" {
		t.Fatalf("status=%q want healthy", status)
	}
	source, _ := got[0]["source"].(string)
	if source != "journal_systemd_dns" {
		t.Fatalf("source=%q want journal_systemd_dns", source)
	}
}
