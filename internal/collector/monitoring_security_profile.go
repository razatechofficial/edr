package collector

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/razatechofficial/edr/internal/config"
)

// IsRegulatedMonitoring reports whether cfg requests regulated (no stub pillars, inventory on).
func IsRegulatedMonitoring(cfg config.Config) bool {
	p := strings.TrimSpace(cfg.Monitoring.SecurityProfile)
	return strings.EqualFold(p, "regulated") || strings.EqualFold(p, "strict_complete")
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
	seen := map[string]bool{}
	for _, c := range cols {
		seen[c.Name()] = true
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
	if strings.EqualFold(strings.TrimSpace(cfg.Monitoring.SecurityProfile), "strict_complete") {
		required := StrictMandatorySources(cfg)
		for _, name := range required {
			if !seen[name] {
				return fmt.Errorf("strict_complete monitoring.security_profile: required collector %q is missing", name)
			}
		}
	}
	return nil
}

// StrictMandatorySources defines explicit OS-specific strict profile pillars.
func StrictMandatorySources(cfg config.Config) []string {
	// Strict profile is complete-by-design but must remain OS-achievable.
	// Keep this matrix aligned with cmd/agent/perOSExpectedSources so strict
	// validation fails only on true implementation drift.
	base := strictBaseMandatorySourcesForGOOS(runtime.GOOS, cfg)
	if WantKernelTier(cfg) {
		base = append(base, "kernel")
	}
	if cfg.Monitoring.PostureEnabled {
		base = append(base, "posture")
	}
	if LogTailPathsConfigured(cfg) {
		base = append(base, "log_tail")
	}
	return base
}

func strictBaseMandatorySourcesForGOOS(goos string, cfg config.Config) []string {
	switch goos {
	case "linux":
		return []string{"process", "file", "network", "auth", "dns", "registry", "inventory"}
	case "darwin":
		// Darwin DNS is strict-required only when at least one concrete Darwin DNS
		// source is configured/enabled. Without this gate, strict could require dns
		// even when the host has no achievable DNS source path (no unified log flag,
		// no alt log stream flag, and no readable configured path).
		base := []string{"process", "file", "network", "auth", "registry", "inventory"}
		if cfg.Monitoring.DarwinUnifiedLogDNS || cfg.Monitoring.DarwinLogStreamDNSAlt || len(cfg.Monitoring.DarwinDNSExtraLogPaths) > 0 {
			base = append(base, "dns")
		}
		return base
	case "windows":
		// Strict/regulated wiring always attaches DNS Client ETW on Windows.
		return []string{"process", "file", "network", "auth", "dns", "registry", "inventory"}
	default:
		// Rare GOOS has complete userland contract pillars (process/file/network/auth/dns/registry)
		// plus inventory; kernel remains conditional on explicit kernel-tier policy.
		return []string{"process", "file", "network", "auth", "dns", "registry", "inventory"}
	}
}
