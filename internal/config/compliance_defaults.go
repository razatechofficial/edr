package config

import "runtime"

// DefaultCompliancePostureProbes returns posture probe names per OS for compliance mode.
func DefaultCompliancePostureProbes() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{
			"posture_hidden_pid",
			"posture_hidden_port",
			"posture_dev_walker",
			"posture_promisc_if",
			"dev_anomaly",
			"rootkit_iocs",
			"ld_so_preload_hash",
		}
	case "darwin":
		return []string{
			"posture_darwin_gatekeeper",
			"posture_darwin_xprotect",
			"posture_darwin_sysext",
			"posture_darwin_codesign",
		}
	case "windows":
		return []string{
			"posture_win_amsi",
			"posture_win_defender_excl",
			"posture_win_bcd",
			"posture_win_wmi",
		}
	default:
		return nil
	}
}

// ApplyComplianceDefaults wires posture/rootcheck collectors when compliance
// (SCA) is enabled. Called during config load after YAML merge.
func ApplyComplianceDefaults(cfg *Config) {
	if cfg == nil || !cfg.Compliance.Enabled {
		return
	}
	if cfg.Compliance.EnablePosture && len(cfg.Monitoring.PostureProbes) == 0 {
		if probes := DefaultCompliancePostureProbes(); len(probes) > 0 {
			cfg.Monitoring.PostureProbes = probes
			cfg.Monitoring.PostureEnabled = true
		}
	}
	if cfg.Compliance.EnableRootcheck && runtime.GOOS == "linux" {
		cfg.Monitoring.LinuxRootcheckEnabled = true
		cfg.Monitoring.LinuxRootcheckPortScan = true
		if cfg.Monitoring.LinuxRootcheckIntervalSec <= 0 {
			cfg.Monitoring.LinuxRootcheckIntervalSec = 43200 // 12h default interval
		}
	}
}
