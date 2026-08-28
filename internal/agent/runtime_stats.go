package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const runtimeStatsName = "runtime_stats.json"

func (a *Agent) maybeWriteRuntimeStats() {
	if a == nil || a.cfg.Agent.DataDir == "" {
		return
	}
	a.healthMu.Lock()
	if !a.lastRuntimeStats.IsZero() && time.Since(a.lastRuntimeStats) < time.Second {
		a.healthMu.Unlock()
		return
	}
	a.lastRuntimeStats = time.Now()
	a.healthMu.Unlock()

	st := struct {
		EventsProcessed uint64 `json:"events_processed"`
		AlertsGenerated uint64 `json:"alerts_generated,omitempty"`
		UpdatedAt       string `json:"updated_at"`
	}{
		EventsProcessed: a.eventsProcessed.Load(),
		UpdatedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	if a.advEngine != nil {
		st.AlertsGenerated = a.advEngine.Stats().DetectionsEmitted
	}
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(a.cfg.Agent.DataDir, runtimeStatsName), b, 0o644)
}
