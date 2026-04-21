//go:build linux

package collector

import (
	"log/slog"
	"os"

	"github.com/razatechofficial/edr/internal/config"
)

const bpfObjectInstallPath = "/var/lib/edr/bpf/edr.bpf.o"

// LogMonitoringBootstrap logs Linux eBPF readiness (object on disk, uid, cap hints).
func LogMonitoringBootstrap(logger *slog.Logger, cfg config.Config) {
	if logger == nil {
		return
	}
	if cfg.Monitoring.Mode == "userland" || !cfg.Monitoring.KernelEnabled {
		logger.Info("monitoring bootstrap", "tier", "userland_config", "kernel_hooks", false)
		return
	}
	if os.Getuid() != 0 {
		logger.Warn("monitoring bootstrap", "tier", "degraded", "reason", "eBPF requires root", "uid", os.Getuid())
		return
	}
	fi, err := os.Stat(bpfObjectInstallPath)
	if err != nil {
		logger.Warn("monitoring bootstrap", "tier", "degraded", "reason", "bpf object missing", "path", bpfObjectInstallPath, "error", err)
		return
	}
	if fi.IsDir() {
		logger.Warn("monitoring bootstrap", "tier", "degraded", "reason", "bpf path is directory", "path", bpfObjectInstallPath)
		return
	}
	logger.Info("monitoring bootstrap", "tier", "kernel_hooks", "bpf_object", bpfObjectInstallPath, "size", fi.Size())
}
