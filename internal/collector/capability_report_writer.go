package collector

// Emission of the kernel capability self-report.
//
// The report is written to its own file rather than merged into
// monitoring_health.json. Two reasons. It answers a different question —
// monitoring_health.json reports how the pipeline is performing (rates, drops,
// queue depth), while this reports whether each event category is being
// monitored at all — and it has its own schema version, so the console can
// adopt a new capability shape without the health file's consumers moving in
// step. Merging them would couple two independent contracts.

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/razatechofficial/edr/internal/kernel"
)

// CapabilityReportFileName is the file written under the agent data directory.
const CapabilityReportFileName = "capability_report.json"

// WriteCapabilityReport writes the driver's capability self-report to
// <dataDir>/capability_report.json.
//
// A driver that does not implement kernel.CapabilityReporter is skipped
// silently: that is an older or stub driver, not a failure, and the absence of
// the file is itself the correct signal. Errors are logged at debug and never
// propagated, matching WriteMonitoringHealth: failing to write a diagnostic
// must not take down collection.
//
// The write is atomic. The console polls this file, and a reader that catches
// a partial write would see a malformed report and could reasonably conclude
// the agent is not monitoring anything.
func WriteCapabilityReport(dataDir string, driver any, log *slog.Logger) {
	if dataDir == "" {
		return
	}
	reporter, ok := driver.(kernel.CapabilityReporter)
	if !ok {
		return
	}

	rep := reporter.CapabilityReport()
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		if log != nil {
			log.Debug("capability report marshal", "error", err)
		}
		return
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		if log != nil {
			log.Debug("capability report mkdir", "error", err)
		}
		return
	}

	final := filepath.Join(dataDir, CapabilityReportFileName)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		if log != nil {
			log.Debug("capability report write", "error", err)
		}
		return
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		if log != nil {
			log.Debug("capability report rename", "error", err)
		}
	}
}
