package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
)

func TestRunMonitoringValidation_NilConfig(t *testing.T) {
	rep := runMonitoringValidation(context.Background(), nil)
	if rep.Failed == 0 {
		t.Fatal("expected failure when cfg is nil")
	}
	findFailedName(t, rep.Assertions, "data_dir")
}

func TestRunMonitoringValidation_EmptyDataDir(t *testing.T) {
	cfg := &config.Config{}
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed == 0 {
		t.Fatal("expected failure when data_dir empty")
	}
	findFailedName(t, rep.Assertions, "data_dir")
}

func TestRunMonitoringValidation_MissingHealthFile(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Agent.DataDir = dir
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed == 0 {
		t.Fatal("expected failure when monitoring_health.json missing")
	}
	findFailedName(t, rep.Assertions, "health_file_present")
}

func TestRunMonitoringValidation_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "monitoring_health.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Agent.DataDir = dir
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed == 0 {
		t.Fatal("expected failure on invalid JSON")
	}
	findFailedName(t, rep.Assertions, "health_file_json")
}

func TestRunMonitoringValidation_SchemaVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	cfg := testMonitoringConfig(dir)
	want := perOSExpectedSources(cfg)
	if len(want) == 0 {
		t.Skip("no expected sources on this GOOS")
	}
	sources := make([]map[string]any, 0, len(want))
	for _, name := range want {
		sources = append(sources, map[string]any{"name": name, "status": "healthy"})
	}
	writeMonitoringHealthFixtureWithSchema(t, dir, 10, sources, 999)
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed == 0 {
		t.Fatal("expected schema failure")
	}
	findFailedName(t, rep.Assertions, "health_schema_version")
}

func TestRunMonitoringValidation_RegulatedExpectsInventoryRow(t *testing.T) {
	dir := t.TempDir()
	defs := config.Defaults()
	cfg := &defs
	cfg.Agent.DataDir = dir
	cfg.Monitoring.SecurityProfile = "regulated"
	cfg.Monitoring.Mode = "userland"
	cfg.Monitoring.KernelEnabled = false

	want := perOSExpectedSources(cfg)
	if !containsWant(want, "inventory") {
		t.Fatalf("regulated should require inventory in expected list: %v", want)
	}
	sources := make([]map[string]any, 0, len(want))
	for _, name := range want {
		if name == "inventory" {
			continue
		}
		sources = append(sources, map[string]any{"name": name, "status": "healthy", "dropped": float64(0)})
	}
	writeMonitoringHealthFixture(t, dir, 42, sources)
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed == 0 {
		t.Fatal("expected missing inventory row to fail")
	}
	findFailedName(t, rep.Assertions, "source.inventory")
}

func testMonitoringConfig(dir string) *config.Config {
	c := &config.Config{}
	c.Agent.DataDir = dir
	c.Monitoring.Mode = "userland"
	c.Monitoring.KernelEnabled = false
	return c
}

func TestRunMonitoringValidation_AllExpectedSourcesHealthy(t *testing.T) {
	dir := t.TempDir()
	cfg := testMonitoringConfig(dir)
	want := perOSExpectedSources(cfg)
	if len(want) == 0 {
		t.Skip("no expected sources on this GOOS")
	}
	sources := make([]map[string]any, 0, len(want))
	for _, name := range want {
		sources = append(sources, map[string]any{"name": name, "status": "healthy", "dropped": float64(0)})
	}
	writeMonitoringHealthFixture(t, dir, 42, sources)
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed != 0 {
		t.Fatalf("unexpected failures Failed=%d details=%v", rep.Failed, rep.Assertions)
	}
}

func TestRunMonitoringValidation_HeapExceedsBudget(t *testing.T) {
	dir := t.TempDir()
	cfg := testMonitoringConfig(dir)
	want := perOSExpectedSources(cfg)
	if len(want) == 0 {
		t.Skip("no expected sources")
	}
	budget := uint64(250)
	if runtime.GOOS == "darwin" {
		budget = 200
	}
	sources := make([]map[string]any, 0, len(want))
	for _, name := range want {
		sources = append(sources, map[string]any{"name": name, "status": "healthy"})
	}
	writeMonitoringHealthFixture(t, dir, float64(budget+80), sources)
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed == 0 {
		t.Fatal("expected heap budget failure")
	}
	findFailedName(t, rep.Assertions, "heap_alloc_mib")
}

func TestRunMonitoringValidation_MissingSource(t *testing.T) {
	dir := t.TempDir()
	cfg := testMonitoringConfig(dir)
	want := perOSExpectedSources(cfg)
	if !containsWant(want, "auth") {
		t.Skip("auth not in expected tier for this GOOS")
	}
	var rows []map[string]any
	for _, name := range want {
		if name == "auth" {
			continue
		}
		rows = append(rows, map[string]any{"name": name, "status": "healthy"})
	}
	writeMonitoringHealthFixture(t, dir, 10, rows)
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed == 0 {
		t.Fatal("expected missing source failure")
	}
	findFailedName(t, rep.Assertions, "source.auth")
}

func TestWriteMonitoringReportCreatesFile(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Agent.DataDir = dir
	rep := MonitoringReport{Timestamp: time.Now().UTC(), OS: runtime.GOOS, Failed: 0}
	writeMonitoringReport(cfg, rep)
	path := filepath.Join(dir, "monitoring_report.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected report written: %v", err)
	}
	var decoded MonitoringReport
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.OS != runtime.GOOS {
		t.Fatalf("os=%q", decoded.OS)
	}
}

func writeMonitoringHealthFixture(t *testing.T, dir string, heapMiB float64, sources []map[string]any) {
	t.Helper()
	list := make([]any, len(sources))
	for i := range sources {
		list[i] = sources[i]
	}
	snap := map[string]any{
		"schema_version": float64(collector.MonitoringHealthSchemaVersion),
		"updated_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"os":             runtime.GOOS,
		"runtime": map[string]any{
			"num_goroutine":  float64(8),
			"heap_alloc_mib": heapMiB,
			"num_gc":         float64(1),
		},
		"sources": list,
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "monitoring_health.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeMonitoringHealthFixtureWithSchema(t *testing.T, dir string, heapMiB float64, sources []map[string]any, schemaVersion int) {
	t.Helper()
	list := make([]any, len(sources))
	for i := range sources {
		list[i] = sources[i]
	}
	snap := map[string]any{
		"schema_version": float64(schemaVersion),
		"updated_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"os":             runtime.GOOS,
		"runtime": map[string]any{
			"num_goroutine":  float64(8),
			"heap_alloc_mib": heapMiB,
			"num_gc":         float64(1),
		},
		"sources": list,
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "monitoring_health.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunMonitoringValidation_KernelAbsentPassesWhenRequireKernelFalse(t *testing.T) {
	dir := t.TempDir()
	defs := config.Defaults()
	cfg := &defs
	cfg.Agent.DataDir = dir
	cfg.Monitoring.RequireKernel = false
	want := perOSExpectedSources(cfg)
	if !containsWant(want, "kernel") {
		t.Skip("kernel not expected on this config/os")
	}
	sources := make([]map[string]any, 0, len(want))
	for _, name := range want {
		if name == "kernel" {
			sources = append(sources, map[string]any{"name": "kernel", "status": "absent", "dropped": float64(0)})
			continue
		}
		sources = append(sources, map[string]any{"name": name, "status": "healthy", "dropped": float64(0)})
	}
	writeMonitoringHealthFixture(t, dir, 42, sources)
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed != 0 {
		t.Fatalf("kernel absent must not fail validation when require_kernel=false: %#v", rep.Assertions)
	}
}

func TestRunMonitoringValidation_KernelAbsentFailsWhenRequireKernelTrue(t *testing.T) {
	dir := t.TempDir()
	defs := config.Defaults()
	cfg := &defs
	cfg.Agent.DataDir = dir
	cfg.Monitoring.RequireKernel = true
	want := perOSExpectedSources(cfg)
	if !containsWant(want, "kernel") {
		t.Skip("kernel not expected on this config/os")
	}
	sources := make([]map[string]any, 0, len(want))
	for _, name := range want {
		if name == "kernel" {
			sources = append(sources, map[string]any{"name": "kernel", "status": "absent"})
			continue
		}
		sources = append(sources, map[string]any{"name": name, "status": "healthy", "dropped": float64(0)})
	}
	writeMonitoringHealthFixture(t, dir, 42, sources)
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed == 0 {
		t.Fatal("expected failure when kernel absent and require_kernel=true")
	}
	findFailedName(t, rep.Assertions, "source.kernel")
}

func TestMonitoringValidation_SoakSmoke(t *testing.T) {
	if os.Getenv("EDR_SOAK_MONITORING") == "" {
		t.Skip("set EDR_SOAK_MONITORING=1 to run monitoring soak smoke")
	}
	dir := t.TempDir()
	defs := config.Defaults()
	defs.Agent.DataDir = dir
	cfg := &defs
	want := perOSExpectedSources(cfg)
	sources := make([]map[string]any, 0, len(want))
	for _, name := range want {
		if name == "kernel" {
			sources = append(sources, map[string]any{"name": name, "status": "absent", "dropped": float64(0)})
			continue
		}
		sources = append(sources, map[string]any{"name": name, "status": "healthy", "dropped": float64(0)})
	}
	writeMonitoringHealthFixture(t, dir, 42, sources)
	rep := runMonitoringValidation(context.Background(), cfg)
	if rep.Failed != 0 {
		t.Fatalf("soak smoke validation failed: %#v", rep.Assertions)
	}
}

func containsWant(want []string, name string) bool {
	for _, w := range want {
		if w == name {
			return true
		}
	}
	return false
}

func findFailedName(t *testing.T, assertions []monitoringAssertion, substr string) {
	t.Helper()
	for _, a := range assertions {
		if a.Failed && a.Name == substr {
			return
		}
	}
	t.Fatalf("no failed assertion matching %q in %#v", substr, assertions)
}
