package platform

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const runtimeStatsName = "runtime_stats.json"

type runtimeStatsFile struct {
	EventsProcessed uint64 `json:"events_processed"`
	AlertsGenerated uint64 `json:"alerts_generated,omitempty"`
}

// RuntimeStatsPath is the on-disk sidecar the sensor writes for the operator UI
// when the local control API is not listening.
func RuntimeStatsPath(dataDir string) string {
	if dataDir == "" {
		dataDir = DataDir()
	}
	return filepath.Join(dataDir, runtimeStatsName)
}

// ReadRuntimeStatsEvents returns events_processed from runtime_stats.json.
func ReadRuntimeStatsEvents(dataDir string) uint64 {
	raw, err := os.ReadFile(RuntimeStatsPath(dataDir))
	if err != nil || len(raw) == 0 {
		return 0
	}
	var st runtimeStatsFile
	if json.Unmarshal(raw, &st) != nil {
		return 0
	}
	return st.EventsProcessed
}
