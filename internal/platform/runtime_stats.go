package platform

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const runtimeStatsName = "runtime_stats.json"

type runtimeStatsFile struct {
	EventsProcessed uint64  `json:"events_processed"`
	AlertsGenerated uint64  `json:"alerts_generated,omitempty"`
	CPUPercent      float64 `json:"cpu_percent,omitempty"`
	MemoryMB        float64 `json:"memory_mb,omitempty"`
}

// ReadRuntimeStatsResources is the sensor's own working-set and CPU share.
func ReadRuntimeStatsResources(dataDir string) (cpu, memMB float64, ok bool) {
	raw, err := os.ReadFile(RuntimeStatsPath(dataDir))
	if err != nil || len(raw) == 0 {
		return 0, 0, false
	}
	var st runtimeStatsFile
	if json.Unmarshal(raw, &st) != nil {
		return 0, 0, false
	}
	if st.MemoryMB <= 0 && st.CPUPercent <= 0 {
		return 0, 0, false
	}
	return st.CPUPercent, st.MemoryMB, true
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
