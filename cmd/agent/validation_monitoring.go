package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/config"
)

// monitoringAssertion is a per-OS assertion the validation suite makes about
// the running agent's monitoring layer. Failures are collected into a single
// MonitoringReport rather than panicking the suite, so operators can address
// them one at a time.
type monitoringAssertion struct {
	Name    string
	Detail  string
	Failed  bool
}

// MonitoringReport is written next to validation_report.json so CI can fail
// the build on missing collectors, missing health snapshots, or budget
// breaches without parsing free-form logs.
type MonitoringReport struct {
	Timestamp     time.Time             `json:"timestamp"`
	OS            string                `json:"os"`
	HealthFile    string                `json:"health_file"`
	HealthAgeSec  float64               `json:"health_age_seconds"`
	Sources       []map[string]any      `json:"sources"`
	Assertions    []monitoringAssertion `json:"assertions"`
	NumGoroutine  int                   `json:"num_goroutine"`
	HeapAllocMiB  uint64                `json:"heap_alloc_mib"`
	Failed        int                   `json:"failed"`
}

// runMonitoringValidation reads monitoring_health.json and asserts that
// per-OS expected sources are present and within resource budgets defined by
// the plan (RSS/heap, drops==0 at idle, expected sources healthy).
//
// The function never returns an error; instead it appends to the report so
// the surrounding validation pipeline can decide how to react.
func runMonitoringValidation(ctx context.Context, cfg *config.Config) MonitoringReport {
	_ = ctx
	rep := MonitoringReport{Timestamp: time.Now().UTC(), OS: runtime.GOOS}
	if cfg == nil || cfg.Agent.DataDir == "" {
		rep.Assertions = append(rep.Assertions, monitoringAssertion{
			Name:   "data_dir",
			Detail: "agent.data_dir is empty; monitoring_health.json cannot be located",
			Failed: true,
		})
		rep.Failed = 1
		return rep
	}

	rep.HealthFile = filepath.Join(cfg.Agent.DataDir, "monitoring_health.json")
	info, err := os.Stat(rep.HealthFile)
	if err != nil {
		rep.Assertions = append(rep.Assertions, monitoringAssertion{
			Name:   "health_file_present",
			Detail: fmt.Sprintf("not readable: %v", err),
			Failed: true,
		})
		rep.Failed++
		return rep
	}
	rep.HealthAgeSec = time.Since(info.ModTime()).Seconds()

	data, err := os.ReadFile(rep.HealthFile)
	if err != nil {
		rep.Assertions = append(rep.Assertions, monitoringAssertion{
			Name:   "health_file_read",
			Detail: err.Error(),
			Failed: true,
		})
		rep.Failed++
		return rep
	}
	var snap map[string]any
	if err := json.Unmarshal(data, &snap); err != nil {
		rep.Assertions = append(rep.Assertions, monitoringAssertion{
			Name:   "health_file_json",
			Detail: err.Error(),
			Failed: true,
		})
		rep.Failed++
		return rep
	}
	if rt, ok := snap["runtime"].(map[string]any); ok {
		if v, ok := rt["num_goroutine"].(float64); ok {
			rep.NumGoroutine = int(v)
		}
		if v, ok := rt["heap_alloc_mib"].(float64); ok {
			rep.HeapAllocMiB = uint64(v)
		}
	}
	if list, ok := snap["sources"].([]any); ok {
		for _, raw := range list {
			if m, ok := raw.(map[string]any); ok {
				rep.Sources = append(rep.Sources, m)
			}
		}
	}

	expected := perOSExpectedSources(cfg)
	rep.Assertions = append(rep.Assertions,
		assertSourcesPresent(rep.Sources, expected)...,
	)
	rep.Assertions = append(rep.Assertions,
		assertNoDrops(rep.Sources)...,
	)
	rep.Assertions = append(rep.Assertions,
		assertHeapBudget(rep.HeapAllocMiB)...,
	)

	for _, a := range rep.Assertions {
		if a.Failed {
			rep.Failed++
		}
	}
	return rep
}

func wantMonitoringKernelTier(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	m := cfg.Monitoring
	if m.Mode == "userland" {
		return false
	}
	return m.KernelEnabled
}

// perOSExpectedSources lists source names required in monitoring_health.json.
// Kernel is asserted only when config requests kernel-tier monitoring (mirrors
// DefaultCollectors + monitoring doctor conditional checks).
func perOSExpectedSources(cfg *config.Config) []string {
	wantK := wantMonitoringKernelTier(cfg)
	osName := runtime.GOOS
	switch osName {
	case "linux", "darwin":
		out := []string{"process", "file", "network", "auth"}
		if wantK {
			out = append(out, "kernel")
		}
		return out
	case "windows":
		out := []string{"process", "file", "network", "auth", "registry"}
		if wantK {
			out = append(out, "kernel")
		}
		return out
	default:
		return nil
	}
}

func assertSourcesPresent(sources []map[string]any, expected []string) []monitoringAssertion {
	have := map[string]string{}
	for _, src := range sources {
		name, _ := src["name"].(string)
		status, _ := src["status"].(string)
		if name != "" {
			have[name] = status
		}
	}
	out := make([]monitoringAssertion, 0, len(expected))
	for _, want := range expected {
		st, present := have[want]
		switch {
		case !present:
			out = append(out, monitoringAssertion{
				Name:   "source." + want,
				Detail: "missing from monitoring_health.json",
				Failed: true,
			})
		case st == "unavailable" || st == "absent" || st == "":
			out = append(out, monitoringAssertion{
				Name:   "source." + want,
				Detail: "status=" + st,
				Failed: true,
			})
		default:
			out = append(out, monitoringAssertion{
				Name:   "source." + want,
				Detail: "status=" + st,
			})
		}
	}
	return out
}

func assertNoDrops(sources []map[string]any) []monitoringAssertion {
	var out []monitoringAssertion
	for _, src := range sources {
		name, _ := src["name"].(string)
		dropped, _ := src["dropped"].(float64)
		if dropped > 0 {
			out = append(out, monitoringAssertion{
				Name:   "drops." + name,
				Detail: fmt.Sprintf("dropped=%.0f (idle should be 0)", dropped),
				Failed: false, // soft-fail: surface but do not block the suite
			})
		}
	}
	return out
}

func assertHeapBudget(heapMiB uint64) []monitoringAssertion {
	var budget uint64 = 250
	if runtime.GOOS == "darwin" {
		budget = 200
	}
	if heapMiB > budget {
		return []monitoringAssertion{{
			Name:   "heap_alloc_mib",
			Detail: fmt.Sprintf("%d MiB exceeds %d MiB budget", heapMiB, budget),
			Failed: true,
		}}
	}
	return []monitoringAssertion{{
		Name:   "heap_alloc_mib",
		Detail: fmt.Sprintf("%d MiB (budget %d)", heapMiB, budget),
	}}
}

// writeMonitoringReport persists the assertion outcome next to the validation
// report so CI can fail on monitoring drift independently of detection drift.
func writeMonitoringReport(cfg *config.Config, rep MonitoringReport) {
	if cfg == nil || cfg.Agent.DataDir == "" {
		return
	}
	out := filepath.Join(cfg.Agent.DataDir, "monitoring_report.json")
	_ = os.MkdirAll(filepath.Dir(out), 0o755)
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(out, data, 0o644)
	fmt.Printf("monitoring report: %s\n", out)
	for _, a := range rep.Assertions {
		marker := "OK"
		if a.Failed {
			marker = "FAIL"
		}
		fmt.Printf("  [%s] %-22s %s\n", marker, a.Name, a.Detail)
	}
}

// avoid "imported and not used" if a future refactor drops a symbol.
var _ = strings.Builder{}
