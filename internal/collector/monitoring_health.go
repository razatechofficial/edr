package collector

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/razatechofficial/edr/internal/config"
)

// ExportMonitoringHealth is implemented by collectors that expose kernel ring/driver stats.
type ExportMonitoringHealth interface {
	ExportMonitoringHealth() map[string]any
}

// WriteMonitoringHealth writes a small JSON snapshot for edrctl monitoring doctor.
func WriteMonitoringHealth(cfg config.Config, collectors []Collector, log *slog.Logger) {
	if cfg.Agent.DataDir == "" {
		return
	}
	out := map[string]any{
		"updated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"os":         runtime.GOOS,
	}
	for _, c := range collectors {
		if h, ok := c.(ExportMonitoringHealth); ok {
			if snap := h.ExportMonitoringHealth(); snap != nil {
				out["kernel"] = snap
				break
			}
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
