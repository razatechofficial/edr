//go:build !linux

package collector

import (
	"log/slog"
	"os"
	"runtime"

	"github.com/razatechofficial/edr/internal/config"
)

// LogMonitoringBootstrap logs non-Linux runtime readiness hints.
func LogMonitoringBootstrap(logger *slog.Logger, cfg config.Config) {
	if logger == nil {
		return
	}
	if cfg.Monitoring.Mode == "userland" || !cfg.Monitoring.KernelEnabled {
		logger.Info("monitoring bootstrap", "tier", "userland_config", "kernel_hooks", false, "goos", runtime.GOOS)
		return
	}
	switch runtime.GOOS {
	case "darwin":
		logger.Info("monitoring bootstrap", "tier", "kernel_requested", "goos", "darwin", "cgo", cgoEnabledForProbe(), "euid", os.Geteuid())
	case "windows":
		logger.Info("monitoring bootstrap", "tier", "kernel_requested", "goos", "windows", "elevated_hint", "see kernel capability probe")
	default:
		logger.Info("monitoring bootstrap", "tier", "kernel_requested", "goos", runtime.GOOS, "note", "capability probe path")
	}
}
