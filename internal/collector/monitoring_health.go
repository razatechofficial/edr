package collector

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/config"
)

// MonitoringHealthSchemaVersion increments when monitoring_health.json semantics change materially.
const MonitoringHealthSchemaVersion = 2

// Kernel-tier monitoring_health extras (schema v2+) may include tamper-adjacent counters:
//   - ebpf_program_missing_events (Linux)
//   - etw_session_recover_attempts (Windows)
//   - tamper_esf_auth_denials (macOS ESF, when policy denies)
//
// All phases should prefer a normalized `tamper` object in kernel source rows:
//   tamper.component, tamper.posture, tamper.signals

// ExportMonitoringHealth is implemented by collectors that publish driver- or
// source-level statistics (eBPF/ETW/ESF ring depth, EPS, drops, last error).
// Returning a nil map means "no data available right now" and the collector
// is silently skipped by WriteMonitoringHealth.
type ExportMonitoringHealth interface {
	ExportMonitoringHealth() map[string]any
}

// ExportMonitoringHealthMulti emits multiple monitoring_health source rows
// (e.g. per log_target.*) without registering a collector per row.
type ExportMonitoringHealthMulti interface {
	ExportMonitoringHealthRows() []map[string]any
}

// MonitoringSource is the canonical per-collector record shape that callers
// SHOULD return from ExportMonitoringHealth(). Returning a map[string]any
// remains supported for back-compat; this struct exists so collectors emit a
// stable schema and the doctor command can render uniform tables.
type MonitoringSource struct {
	Name          string `json:"name"`            // e.g. "process", "file", "network"
	OS            string `json:"os"`              // runtime.GOOS
	Source        string `json:"source"`          // "ebpf", "etw", "esf", "fsnotify", ...
	Status        string `json:"status"`          // "healthy" | "degraded" | "unavailable" | "absent"
	EPSIn         uint64 `json:"eps_in"`          // events received last second
	EPSOut        uint64 `json:"eps_out"`         // events emitted last second
	Dropped       uint64 `json:"dropped"`         // channel/backpressure drops; optional map key rate_limited_drops = stream_max_eps path (streaming_run_collector).
	QueueDepth    int    `json:"queue_depth"`     // current outbound queue length
	LastError     string `json:"last_error"`      // empty string when none
	LastEventUnix int64  `json:"last_event_unix"` // unix seconds; 0 if never
	Notes         string `json:"notes,omitempty"` // optional free-form context

	// Kernel tier / ring buffer (schema v2+).
	RingBytesUsed     uint64  `json:"ring_bytes_used,omitempty"`
	RingCapacityBytes uint64  `json:"ring_capacity_bytes,omitempty"`
	RingBacklogPct    float64 `json:"ring_backlog_pct,omitempty"`
	// ETW/ESF ingest queues (callback → worker).
	IngestQueueDepth int    `json:"ingest_queue_depth,omitempty"`
	IngestQueueCap   int    `json:"ingest_queue_cap,omitempty"`
	IngestDropped    uint64 `json:"ingest_dropped,omitempty"`
}

// ToMap renders the record into the loose map[string]any shape used by
// ExportMonitoringHealth implementations. Extra keys such as rate_limited_drops
// may be merged by callers (streaming collectors EPS cap path; see streaming_run_collector.go).
func (m MonitoringSource) ToMap() map[string]any {
	out := map[string]any{
		"name":            m.Name,
		"os":              m.OS,
		"source":          m.Source,
		"status":          m.Status,
		"eps_in":          m.EPSIn,
		"eps_out":         m.EPSOut,
		"dropped":         m.Dropped,
		"queue_depth":     m.QueueDepth,
		"last_event_unix": m.LastEventUnix,
	}
	if m.LastError != "" {
		out["last_error"] = m.LastError
	}
	if m.Notes != "" {
		out["notes"] = m.Notes
	}
	if m.RingBytesUsed > 0 {
		out["ring_bytes_used"] = m.RingBytesUsed
	}
	if m.RingCapacityBytes > 0 {
		out["ring_capacity_bytes"] = m.RingCapacityBytes
	}
	if m.RingBacklogPct > 0 {
		out["ring_backlog_pct"] = m.RingBacklogPct
	}
	if m.IngestQueueDepth > 0 {
		out["ingest_queue_depth"] = m.IngestQueueDepth
	}
	if m.IngestQueueCap > 0 {
		out["ingest_queue_cap"] = m.IngestQueueCap
	}
	if m.IngestDropped > 0 {
		out["ingest_dropped"] = m.IngestDropped
	}
	return out
}

// KernelHealthMap builds a monitoring_health.json row with canonical
// MonitoringSource fields (name=kernel) plus driver and ring-buffer stats.
// extras are merged last (e.g. file_dropped on Windows ETW builds).
func KernelHealthMap(backend string, driverStats, ringBufStats any, extras map[string]any) map[string]any {
	src := MonitoringSource{
		Name:   "kernel",
		OS:     runtime.GOOS,
		Source: backend,
		Status: "healthy",
	}.ToMap()
	src["driver"] = driverStats
	src["ringbuf"] = ringBufStats
	for k, v := range extras {
		src[k] = v
	}
	return src
}

// MergeTamperHealth normalizes anti-tamper posture/signals under one key.
// Optional signals["degraded_reasons"] ([]string or []any) is also copied to tamper.degraded_reason for operators.
func MergeTamperHealth(extras map[string]any, component string, posture map[string]any, signals map[string]any) map[string]any {
	if extras == nil {
		extras = map[string]any{}
	}
	t := map[string]any{
		"component": component,
	}
	if len(posture) > 0 {
		t["posture"] = posture
	}
	if len(signals) > 0 {
		t["signals"] = signals
		if dr, ok := signals["degraded_reasons"].([]string); ok && len(dr) > 0 {
			t["degraded_reason"] = dr
		} else if dr2, ok := signals["degraded_reasons"].([]any); ok && len(dr2) > 0 {
			t["degraded_reason"] = dr2
		}
	}
	extras["tamper"] = t
	return extras
}

// AppendSyntheticKernelAbsentIfNeeded appends name=kernel, status=absent when WantKernelTier
// is true but no prior source row advertised kernel telemetry (elevated/driver/build gaps).
func AppendSyntheticKernelAbsentIfNeeded(cfg config.Config, sources []map[string]any) []map[string]any {
	if !WantKernelTier(cfg) {
		return sources
	}
	for _, s := range sources {
		if name, _ := s["name"].(string); name == "kernel" {
			return sources
		}
	}
	row := MonitoringSource{
		Name:   "kernel",
		OS:     runtime.GOOS,
		Source: "none",
		Status: "absent",
		Notes:  "kernel tier enabled but no kernel collector attached or emitted health; check elevation/root, driver init, entitlement (macOS), or nosec/CGO-less builds",
	}.ToMap()
	return append(sources, row)
}

// runtimeSnapshot captures process-wide go-runtime metrics once per write
// cycle. It is cheap (a few atomic loads) and helps the doctor command spot
// goroutine or memory growth.
type runtimeSnapshot struct {
	NumGoroutine int    `json:"num_goroutine"`
	HeapAllocMiB uint64 `json:"heap_alloc_mib"`
	NumGC        uint32 `json:"num_gc"`
}

func captureRuntimeSnapshot() runtimeSnapshot {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return runtimeSnapshot{
		NumGoroutine: runtime.NumGoroutine(),
		HeapAllocMiB: ms.HeapAlloc / (1024 * 1024),
		NumGC:        ms.NumGC,
	}
}

// WriteMonitoringHealth writes a JSON snapshot consumed by edrctl monitoring
// doctor. It now aggregates *every* collector that implements the interface
// (not just the first one) under "sources" and includes a runtime snapshot.
func WriteMonitoringHealth(cfg config.Config, collectors []Collector, log *slog.Logger) {
	if cfg.Agent.DataDir == "" {
		return
	}
	sources := make([]map[string]any, 0, len(collectors))
	for _, c := range collectors {
		if mh, ok := c.(ExportMonitoringHealthMulti); ok {
			for _, row := range mh.ExportMonitoringHealthRows() {
				if row != nil {
					sources = append(sources, row)
				}
			}
			continue
		}
		h, ok := c.(ExportMonitoringHealth)
		if !ok {
			continue
		}
		snap := h.ExportMonitoringHealth()
		if snap == nil {
			continue
		}
		sources = append(sources, snap)
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.Monitoring.SecurityProfile), "strict_complete") {
		sources = collapseMonitoringSourcesByName(sources)
	}
	sources = AppendSyntheticKernelAbsentIfNeeded(cfg, sources)
	out := map[string]any{
		"schema_version": MonitoringHealthSchemaVersion,
		"updated_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"os":             runtime.GOOS,
		"runtime":        captureRuntimeSnapshot(),
		"sources":        sources,
	}
	// Legacy "kernel" key: prefer the explicit kernel source row.
	for _, s := range sources {
		if name, _ := s["name"].(string); name == "kernel" {
			out["kernel"] = s
			break
		}
	}
	path := filepath.Join(cfg.Agent.DataDir, "monitoring_health.json")
	if err := os.MkdirAll(cfg.Agent.DataDir, 0o755); err != nil {
		if log != nil {
			log.Debug("monitoring health mkdir", "error", err)
		}
		return
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(path, b, 0o644); err != nil && log != nil {
		log.Debug("monitoring health write", "error", err)
	}
}

func collapseMonitoringSourcesByName(in []map[string]any) []map[string]any {
	if len(in) <= 1 {
		return in
	}
	out := make([]map[string]any, 0, len(in))
	byName := make(map[string]int, len(in))
	for _, src := range in {
		name, _ := src["name"].(string)
		if name == "" {
			out = append(out, src)
			continue
		}
		if idx, exists := byName[name]; !exists {
			byName[name] = len(out)
			out = append(out, src)
			continue
		} else {
			out[idx] = preferMonitoringSource(out[idx], src)
		}
	}
	return out
}

func preferMonitoringSource(current, next map[string]any) map[string]any {
	currStatus, _ := current["status"].(string)
	nextStatus, _ := next["status"].(string)
	rank := func(s string) int {
		switch s {
		case "healthy":
			return 4
		case "degraded":
			return 3
		case "unavailable":
			return 2
		case "absent":
			return 1
		default:
			return 0
		}
	}
	if rank(nextStatus) > rank(currStatus) {
		return next
	}
	return current
}
