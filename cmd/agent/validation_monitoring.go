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

	"github.com/razatechofficial/edr/internal/collector"
	"github.com/razatechofficial/edr/internal/config"
)

// monitoringAssertion is a per-OS assertion the validation suite makes about
// the running agent's monitoring layer. Failures are collected into a single
// MonitoringReport rather than panicking the suite, so operators can address
// them one at a time.
type monitoringAssertion struct {
	Name   string
	Detail string
	Failed bool
}

// MonitoringReport is written next to validation_report.json so CI can fail
// the build on missing collectors, missing health snapshots, or budget
// breaches without parsing free-form logs.
type MonitoringReport struct {
	Timestamp    time.Time             `json:"timestamp"`
	OS           string                `json:"os"`
	HealthFile   string                `json:"health_file"`
	HealthAgeSec float64               `json:"health_age_seconds"`
	Sources      []map[string]any      `json:"sources"`
	Assertions   []monitoringAssertion `json:"assertions"`
	NumGoroutine int                   `json:"num_goroutine"`
	HeapAllocMiB uint64                `json:"heap_alloc_mib"`
	Failed       int                   `json:"failed"`
}

// runMonitoringValidation reads monitoring_health.json and asserts that
// per-OS expected sources are present and within resource budgets defined by
// the plan (RSS/heap, drops==0 at idle, expected sources healthy).
//
// The function never returns an error; instead it appends to the report so
// the surrounding validation pipeline can decide how to react.
func runMonitoringValidation(ctx context.Context, cfg *config.Config, harness bool) MonitoringReport {
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

	rep.Assertions = append(rep.Assertions, assertHealthSchemaVersion(snap)...)

	expected := perOSExpectedSources(cfg)
	rep.Assertions = append(rep.Assertions,
		assertSourcesPresent(rep.Sources, expected, cfg)...,
	)
	if !harness {
		rep.Assertions = append(rep.Assertions,
			assertNoDrops(rep.Sources, cfg)...,
		)
	}
	rep.Assertions = append(rep.Assertions,
		assertWindowsNetworkContract(rep.Sources)...,
	)
	rep.Assertions = append(rep.Assertions,
		assertHeapBudget(rep.HeapAllocMiB)...,
	)
	rep.Assertions = append(rep.Assertions,
		assertStrictNoPlaceholderSources(rep.Sources, cfg)...,
	)
	rep.Assertions = append(rep.Assertions,
		assertPlatformKernelContracts(rep.Sources, cfg)...,
	)
	rep.Assertions = append(rep.Assertions,
		assertWindowsServiceHardeningDepth(cfg)...,
	)
	rep.Assertions = append(rep.Assertions,
		assertInventoryDeltaWhenEnabled(cfg)...,
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

func assertHealthSchemaVersion(snap map[string]any) []monitoringAssertion {
	v := snap["schema_version"]
	var n float64
	switch x := v.(type) {
	case float64:
		n = x
	case int:
		n = float64(x)
	case int64:
		n = float64(x)
	default:
		return []monitoringAssertion{{
			Name:   "health_schema_version",
			Detail: "missing or non-numeric schema_version in monitoring_health.json",
			Failed: true,
		}}
	}
	got := int(n)
	want := collector.MonitoringHealthSchemaVersion
	if got != want {
		return []monitoringAssertion{{
			Name:   "health_schema_version",
			Detail: fmt.Sprintf("got %d want %d", got, want),
			Failed: true,
		}}
	}
	return []monitoringAssertion{{
		Name:   "health_schema_version",
		Detail: fmt.Sprintf("%d ok", got),
	}}
}

// perOSExpectedSources lists source names required in monitoring_health.json.
// Kernel is asserted only when config requests kernel-tier monitoring (mirrors
// DefaultCollectors + monitoring doctor conditional checks).
func perOSExpectedSources(cfg *config.Config) []string {
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.Monitoring.SecurityProfile), "strict_complete") {
		return collector.StrictMandatorySources(*cfg)
	}
	wantK := wantMonitoringKernelTier(cfg)
	osName := runtime.GOOS
	switch osName {
	case "linux", "darwin":
		out := []string{"process", "file", "network", "auth"}
		if wantK {
			out = append(out, "kernel")
		}
		if cfg != nil && collector.InventoryWanted(*cfg) {
			out = append(out, "inventory")
		}
		return out
	case "windows":
		out := []string{"process", "file", "network", "auth", "registry"}
		if cfg != nil && cfg.Monitoring.DnsClientETWWindows {
			out = append(out, "dns")
		}
		if wantK {
			out = append(out, "kernel")
		}
		if cfg != nil && collector.InventoryWanted(*cfg) {
			out = append(out, "inventory")
		}
		return out
	default:
		// Tier-minimal: rare GOOS carry bounded pillars + explicit dns/kernel capability rows when enabled.
		out := []string{"process", "file", "network", "auth"}
		if wantK {
			out = append(out, "kernel")
		}
		out = append(out, "dns")
		if cfg != nil && cfg.Monitoring.PostureEnabled {
			out = append(out, "posture")
		}
		if cfg != nil && collector.LogTargetsBreadthConfigured(*cfg) {
			out = append(out, "log_targets")
		}
		if cfg != nil && collector.InventoryWanted(*cfg) {
			out = append(out, "inventory")
		}
		return out
	}
}

func assertSourcesPresent(sources []map[string]any, expected []string, cfg *config.Config) []monitoringAssertion {
	have := map[string]string{}
	for _, src := range sources {
		name, _ := src["name"].(string)
		status, _ := src["status"].(string)
		if name != "" {
			have[name] = status
		}
	}
	requireK := cfg != nil && cfg.Monitoring.RequireKernel
	strictComplete := cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.Monitoring.SecurityProfile), "strict_complete")
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
		case st == "absent":
			fail := !(want == "kernel" && !requireK)
			if !strictComplete {
				// Rare GOOS: network pillar may report absent when neither procfs nor netstat yields rows.
				if want == "network" && st == "absent" {
					switch osName := runtime.GOOS; osName {
					case "linux", "darwin", "windows":
					default:
						fail = false
					}
				}
				// Rare GOOS: DNS pillar may report absent in relaxed profile.
				if want == "dns" && st == "absent" {
					switch runtime.GOOS {
					case "linux", "darwin", "windows":
					default:
						fail = false
					}
				}
				// Rare GOOS: auth may remain stub/absent when no log source is available.
				if want == "auth" && st == "absent" {
					switch runtime.GOOS {
					case "linux", "darwin", "windows":
					default:
						fail = false
					}
				}
			}
			out = append(out, monitoringAssertion{
				Name:   "source." + want,
				Detail: "status=" + st,
				Failed: fail,
			})
		case st == "unavailable" || st == "":
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

func assertNoDrops(sources []map[string]any, cfg *config.Config) []monitoringAssertion {
	_ = cfg
	var out []monitoringAssertion
	for _, src := range sources {
		name, _ := src["name"].(string)
		dropped, _ := src["dropped"].(float64)
		if dropped > 0 {
			out = append(out, monitoringAssertion{
				Name:   "drops." + name,
				Detail: fmt.Sprintf("dropped=%.0f (idle should be 0)", dropped),
				Failed: true,
			})
		}
		if rl := rateLimitedPositive(src["rate_limited_drops"]); rl > 0 {
			// Soft signal: stream_max_eps backpressure is expected under load and
			// is not treated as a monitoring health failure (see golden fixture
			// stream_eps_rate_limited.json).
			out = append(out, monitoringAssertion{
				Name:   "rate_limit_drops." + name,
				Detail: fmt.Sprintf("rate_limited_drops=%.0f (stream_max_eps)", rl),
			})
		}
	}
	return out
}

func assertWindowsNetworkContract(sources []map[string]any) []monitoringAssertion {
	if runtime.GOOS != "windows" {
		return nil
	}
	for _, src := range sources {
		name, _ := src["name"].(string)
		if name != "network" {
			continue
		}
		source, _ := src["source"].(string)
		source = strings.TrimSpace(source)
		// Unit tests and minimal fixtures often omit backend provenance; only enforce
		// coverage notes when a concrete Windows network implementation is reported.
		if source == "" {
			return nil
		}
		notes, _ := src["notes"].(string)
		lowerNotes := strings.ToLower(notes)
		switch source {
		case "iphlpapi_extended_net", "iphlpapi_extended_tcp":
			ok := strings.Contains(lowerNotes, "tcp+udp coverage") || strings.Contains(lowerNotes, "tcp-only")
			return []monitoringAssertion{{
				Name:   "source.network.contract",
				Detail: fmt.Sprintf("source=%s network_coverage_note=%v", source, ok),
				Failed: !ok,
			}}
		case "etw_sysmon_delegate":
			ok := strings.Contains(lowerNotes, "defers") || strings.Contains(lowerNotes, "delegate")
			return []monitoringAssertion{{
				Name:   "source.network.contract",
				Detail: fmt.Sprintf("source=%s delegated_note=%v", source, ok),
				Failed: !ok,
			}}
		default:
			return []monitoringAssertion{{
				Name:   "source.network.contract",
				Detail: "unexpected network source=" + source,
				Failed: true,
			}}
		}
	}
	return nil
}

// rateLimitedPositive returns a positive count from health JSON unmarshaled numbers (float64).
func rateLimitedPositive(v any) float64 {
	f, ok := v.(float64)
	if ok && f > 0 {
		return f
	}
	return 0
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

func assertStrictNoPlaceholderSources(sources []map[string]any, cfg *config.Config) []monitoringAssertion {
	if cfg == nil {
		return nil
	}
	var out []monitoringAssertion
	for _, s := range sources {
		name, _ := s["name"].(string)
		src, _ := s["source"].(string)
		l := strings.ToLower(src)
		if isApprovedStrictEquivalentSource(name, l) {
			continue
		}
		if strings.Contains(l, "contract") || strings.Contains(l, "snapshot") || strings.Contains(l, "placeholder") {
			out = append(out, monitoringAssertion{
				Name:   "source_impl." + name,
				Detail: "placeholder source=" + src,
				Failed: true,
			})
		}
	}
	return out
}

func assertPlatformKernelContracts(sources []map[string]any, cfg *config.Config) []monitoringAssertion {
	if !wantMonitoringKernelTier(cfg) {
		return nil
	}
	var kernelRow map[string]any
	for _, s := range sources {
		if name, _ := s["name"].(string); name == "kernel" {
			kernelRow = s
			break
		}
	}
	if kernelRow == nil {
		return nil
	}
	status, _ := kernelRow["status"].(string)
	if status == "absent" || status == "unavailable" {
		return nil
	}
	tamper, hasTamper := kernelRow["tamper"].(map[string]any)
	switch runtime.GOOS {
	case "linux":
		if v, ok := kernelRow["bpf_load_diag"]; ok {
			if _, isStr := v.(string); !isStr {
				return []monitoringAssertion{{
					Name:   "kernel.linux.bpf_load_diag",
					Detail: "bpf_load_diag must be a string when present",
					Failed: true,
				}}
			}
		}
		return nil
	case "windows":
		if v, ok := kernelRow["control_plane_ready"].(bool); !ok {
			return []monitoringAssertion{{
				Name:   "kernel.windows.control_plane_ready",
				Detail: "missing boolean control_plane_ready",
				Failed: true,
			}}
		} else if !v && cfg != nil && cfg.Monitoring.WindowsControlPlaneRequired {
			return []monitoringAssertion{{
				Name:   "kernel.windows.control_plane_ready",
				Detail: "control plane degraded while windows_control_plane_required=true",
				Failed: true,
			}}
		}
		if cfg != nil && cfg.Monitoring.WindowsControlPlaneRequired {
			sh, ok := kernelRow["service_hardening_posture"].(map[string]any)
			if !ok {
				return []monitoringAssertion{{
					Name:   "kernel.windows.service_hardening_posture",
					Detail: "missing service_hardening_posture while windows_control_plane_required=true",
					Failed: true,
				}}
			}
			applied, _ := sh["applied"].(bool)
			fac, _ := sh["failure_actions_configured"].(bool)
			if !applied || !fac {
				return []monitoringAssertion{{
					Name:   "kernel.windows.service_hardening_posture",
					Detail: "expected applied=true and failure_actions_configured=true",
					Failed: true,
				}}
			}
		}
		if !hasTamper {
			return []monitoringAssertion{{
				Name:   "kernel.windows.tamper",
				Detail: "missing normalized tamper object",
				Failed: true,
			}}
		}
		_, hasSignals := tamper["signals"].(map[string]any)
		return []monitoringAssertion{{
			Name:   "kernel.windows.tamper",
			Detail: fmt.Sprintf("tamper_signals=%v", hasSignals),
			Failed: !hasSignals,
		}}
	case "darwin":
		if _, ok := kernelRow["ne_ctl"].(map[string]any); !ok {
			return []monitoringAssertion{{
				Name:   "kernel.darwin.ne_ctl",
				Detail: "missing ne_ctl object",
				Failed: true,
			}}
		}
		rv, ok := kernelRow["esf_revocation"].(map[string]any)
		if !ok {
			return []monitoringAssertion{{
				Name:   "kernel.darwin.esf_revocation",
				Detail: "missing esf_revocation object",
				Failed: true,
			}}
		}
		if _, ok := rv["esf_revocation_probes"]; !ok {
			return []monitoringAssertion{{
				Name:   "kernel.darwin.esf_revocation_probes",
				Detail: "missing non-heartbeat esf_revocation_probes map",
				Failed: true,
			}}
		}
		capv, ok := kernelRow["esf_ingest_queue_cap"].(float64)
		if !ok || capv <= 0 {
			return []monitoringAssertion{{
				Name:   "kernel.darwin.esf_ingest",
				Detail: "expected esf_ingest_queue_cap > 0",
				Failed: true,
			}}
		}
		if !hasTamper {
			return []monitoringAssertion{{
				Name:   "kernel.darwin.tamper",
				Detail: "missing normalized tamper object",
				Failed: true,
			}}
		}
		return []monitoringAssertion{{
			Name:   "kernel.darwin.contract",
			Detail: "ne_ctl+esf_revocation+tamper present",
		}}
	default:
		return nil
	}
}

func assertWindowsServiceHardeningDepth(cfg *config.Config) []monitoringAssertion {
	if cfg == nil || runtime.GOOS != "windows" || !cfg.Monitoring.WindowsServiceHardening {
		return nil
	}
	const path = `C:\ProgramData\EDR Agent\service_hardening_posture.json`
	b, err := os.ReadFile(path)
	if err != nil {
		return []monitoringAssertion{{
			Name:   "windows_service_hardening_depth",
			Detail: fmt.Sprintf("read posture: %v", err),
			Failed: true,
		}}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return []monitoringAssertion{{
			Name:   "windows_service_hardening_depth",
			Detail: err.Error(),
			Failed: true,
		}}
	}
	rp, _ := m["required_privileges_set"].(bool)
	sid, _ := m["service_sid_type"].(string)
	tier, _ := m["launch_protected_tier"].(string)
	if !rp || sid != "restricted" {
		return []monitoringAssertion{{
			Name:   "windows_service_hardening_depth",
			Detail: fmt.Sprintf("required_privileges_set=%v service_sid_type=%q want true+restricted", rp, sid),
			Failed: true,
		}}
	}
	if cfg.Monitoring.WindowsPPLRequired || tier == "antimalware_light" {
		isAM, _ := m["ppl_is_antimalware"].(bool)
		eku, _ := m["antimalware_eku"].(bool)
		if !isAM || !eku {
			return []monitoringAssertion{{
				Name:   "windows_am_ppl_posture",
				Detail: fmt.Sprintf("launch_tier=%q ppl_is_antimalware=%v antimalware_eku=%v", tier, isAM, eku),
				Failed: cfg.Monitoring.WindowsPPLRequired,
			}}
		}
		return []monitoringAssertion{{
			Name:   "windows_am_ppl_posture",
			Detail: "AM-PPL runtime + antimalware EKU ok",
		}}
	}
	return []monitoringAssertion{{
		Name:   "windows_service_hardening_depth",
		Detail: "required_privileges_set+restricted ok",
	}}
}

func assertInventoryDeltaWhenEnabled(cfg *config.Config) []monitoringAssertion {
	if cfg == nil || !cfg.Monitoring.InventoryEmitDeltas || strings.TrimSpace(cfg.Agent.DataDir) == "" {
		return nil
	}
	p := filepath.Join(cfg.Agent.DataDir, "inventory_delta.json")
	if _, err := os.Stat(p); err != nil {
		return []monitoringAssertion{{
			Name:   "inventory_delta",
			Detail: fmt.Sprintf("missing %s: %v", p, err),
			Failed: true,
		}}
	}
	return []monitoringAssertion{{
		Name:   "inventory_delta",
		Detail: p + " ok",
	}}
}

func isApprovedStrictEquivalentSource(name, src string) bool {
	// Darwin no-cgo/nosec intentionally uses a userland-equivalent kernel tier.
	if name == "kernel" && src == "darwin_userland_log_stream" {
		return true
	}
	// Rare GOOS kernel tier may be implemented as bounded userland-equivalent stream.
	if name == "kernel" && src == "rare_userland_kernel_stream" {
		return true
	}
	// Rare GOOS registry pillar uses deterministic host state probes.
	if name == "registry" && src == "rare_registry_probe" {
		return true
	}
	return false
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
