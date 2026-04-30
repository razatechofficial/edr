package collector

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/razatechofficial/edr/internal/config"
)

// IsRegulatedMonitoring reports whether cfg requests regulated (no stub pillars, inventory on).
func IsRegulatedMonitoring(cfg config.Config) bool {
	return strings.EqualFold(strings.TrimSpace(cfg.Monitoring.SecurityProfile), "regulated")
}

// InventoryWanted is true when L1 inventory collector should attach.
func InventoryWanted(cfg config.Config) bool {
	m := cfg.Monitoring
	if IsRegulatedMonitoring(cfg) {
		return true
	}
	return m.InventoryEnabled
}

// ApplyRegulatedDefaults returns a copy of cfg with regulated defaults applied for collector wiring.
func ApplyRegulatedDefaults(cfg config.Config) config.Config {
	if !IsRegulatedMonitoring(cfg) {
		return cfg
	}
	if runtime.GOOS == "linux" && !cfg.Monitoring.LinuxPIDNetwork {
		cfg.Monitoring.LinuxPIDNetwork = true
	}
	if runtime.GOOS == "darwin" && !cfg.Monitoring.DarwinAttribNetwork {
		cfg.Monitoring.DarwinAttribNetwork = true
	}
	if runtime.GOOS == "windows" && cfg.Monitoring.ETWRegulatedVerbose {
		m := &cfg.Monitoring
		m.ETWWMIActivity = true
		m.ETWPowerShellScript = true
		m.ETWNamedPipeHandles = true
		m.ETWBitsClient = true
		m.ETWTaskScheduler = true
	}
	return cfg
}

// ValidateRegulatedMonitoring returns an error if regulated profile constraints are violated.
func ValidateRegulatedMonitoring(cfg config.Config, cols []Collector) error {
	if !IsRegulatedMonitoring(cfg) {
		return nil
	}
	var inv bool
	for _, c := range cols {
		switch c.(type) {
		case *NetworkStubCollector, *AuthStubCollector, *FileStubCollector:
			return fmt.Errorf("regulated monitoring.security_profile: collector %q is a stub (real implementation required)", c.Name())
		}
		if c.Name() == "inventory" {
			inv = true
		}
	}
	if !inv {
		return fmt.Errorf("regulated monitoring.security_profile: inventory collector is required")
	}
	return nil
}
