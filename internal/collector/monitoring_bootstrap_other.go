//go:build !linux

package collector

import (
	"log/slog"

	"github.com/razatechofficial/edr/internal/config"
)

// LogMonitoringBootstrap is a no-op on non-Linux builds.
func LogMonitoringBootstrap(_ *slog.Logger, _ config.Config) {}
