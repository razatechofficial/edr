package collector

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/config"
)

// InventoryCollector implements L1 baseline snapshots (packages, listeners, OS).
type InventoryCollector struct {
	cfg config.Config

	mu          sync.Mutex
	lastScan    time.Time
	lastSummary map[string]any
	scanCount   uint64
	lastErr     string
	strictNote  string // regulated + inventory_strict_listener_attribution violation text
}

// NewInventoryCollector builds the inventory collector.
func NewInventoryCollector(cfg config.Config) *InventoryCollector {
	return &InventoryCollector{cfg: cfg}
}

func (i *InventoryCollector) Name() string { return "inventory" }

// Collect refreshes inventory on a configured interval.
func (i *InventoryCollector) Collect(ctx context.Context) ([]Telemetry, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	intervalSec := i.cfg.Monitoring.InventoryIntervalSec
	if intervalSec < 0 {
		intervalSec = 0
	}
	minGap := time.Duration(intervalSec) * time.Second
	i.mu.Lock()
	defer i.mu.Unlock()
	if minGap > 0 && !i.lastScan.IsZero() && time.Since(i.lastScan) < minGap {
		return nil, nil
	}

	i.lastScan = time.Now()
	i.strictNote = ""
	sum, err := scanHostInventory(ctx)
	if err != nil {
		i.lastErr = err.Error()
	} else {
		i.lastErr = ""
		i.lastSummary = sum
		if i.cfg.Monitoring.InventoryPersistSnapshots && i.cfg.Agent.DataDir != "" && sum != nil {
			h, changed, snapPath, perr := persistInventorySnapshot(i.cfg.Agent.DataDir, sum)
			if perr != nil {
				i.lastErr = perr.Error()
			} else if h != "" {
				sum["inventory_snapshot_sha256_hex"] = h
				sum["inventory_snapshot_changed"] = changed
				sum["inventory_snapshot_path"] = snapPath
			}
		}
		if IsRegulatedMonitoring(i.cfg) && i.cfg.Monitoring.InventoryStrictListenerAttribution {
			a, _ := sum["inventory_listener_attribution"].(string)
			if a == "count_only" || a == "unavailable" || a == "" {
				i.strictNote = "regulated inventory_strict_listener_attribution: insufficient listener process attribution (got " + a + ")"
			}
		}
	}
	i.scanCount++
	return nil, nil
}

// ExportMonitoringHealth publishes the last snapshot for monitoring_health.json.
func (i *InventoryCollector) ExportMonitoringHealth() map[string]any {
	i.mu.Lock()
	defer i.mu.Unlock()
	st := "healthy"
	lastErr := i.lastErr
	if lastErr != "" {
		st = "degraded"
	}
	notes := strings.TrimSpace(i.strictNote)
	if notes != "" {
		st = "degraded"
	}
	src := MonitoringSource{
		Name:      "inventory",
		OS:        runtime.GOOS,
		Source:    "baseline_scan",
		Status:    st,
		EPSOut:    i.scanCount,
		LastError: lastErr,
		Notes:     notes,
	}.ToMap()
	for k, v := range i.lastSummary {
		src[k] = v
	}
	if len(i.lastSummary) == 0 && lastErr == "" && notes == "" {
		src["status"] = "degraded"
	}
	return src
}
