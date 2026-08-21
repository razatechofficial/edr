package config

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// ValidationErrors collects multiple configuration validation failures and
// implements the error interface.
type ValidationErrors struct {
	Errors []string
}

// Error returns a human-readable summary of all validation failures.
func (ve *ValidationErrors) Error() string {
	return "config validation failed:\n  " + strings.Join(ve.Errors, "\n  ")
}

func (ve *ValidationErrors) add(format string, args ...interface{}) {
	ve.Errors = append(ve.Errors, fmt.Sprintf(format, args...))
}

func (ve *ValidationErrors) err() error {
	if len(ve.Errors) == 0 {
		return nil
	}
	return ve
}

// Validate checks all configuration fields for correctness and returns a
// multi-error describing every violation found. If Agent.ID is empty it is
// automatically populated with a new UUID.
func Validate(cfg *Config) error {
	var errs ValidationErrors

	if cfg.Agent.ID == "" {
		errs.add("agent.id is required (should be set by EnsureAgentIdentity)")
	}

	validateEnum(&errs, "agent.log_level", cfg.Agent.LogLevel,
		"debug", "info", "warn", "error", "critical")

	if cfg.Agent.Environment != "" {
		validateEnum(&errs, "agent.environment", cfg.Agent.Environment,
			"government", "enterprise", "airgap")
	}

	if cfg.Server.GRPCPort != 0 {
		validateRange(&errs, "server.grpc_port", cfg.Server.GRPCPort, 1, 65535)
	}
	if cfg.Server.HeartbeatSec != 0 {
		validateMin(&errs, "server.heartbeat_sec", cfg.Server.HeartbeatSec, 1)
	}
	if cfg.Server.ReconnectSec != 0 {
		validateMin(&errs, "server.reconnect_sec", cfg.Server.ReconnectSec, 1)
	}
	if cfg.Server.Endpoint != "" {
		if cfg.Server.MutualTLS {
			validateFileReadable(&errs, "server.tls_cert", cfg.Server.TLSCertPath)
			validateFileReadable(&errs, "server.tls_key", cfg.Server.TLSKeyPath)
			validateFileReadable(&errs, "server.ca_cert", cfg.Server.CACertPath)
		} else if cfg.Server.CACertPath != "" {
			validateFileReadable(&errs, "server.ca_cert", cfg.Server.CACertPath)
		}
	}

	llmProviders := []string{
		"openai", "anthropic", "grok", "groq", "gemini",
		"azure", "bedrock", "ollama", "llamacpp",
	}
	if cfg.LLM.PrimaryProvider != "" {
		validateEnum(&errs, "llm.primary_provider", cfg.LLM.PrimaryProvider, llmProviders...)
	}
	if cfg.LLM.FallbackProvider != "" {
		validateEnum(&errs, "llm.fallback_provider", cfg.LLM.FallbackProvider, llmProviders...)
	}
	if cfg.LLM.LocalProvider != "" {
		validateEnum(&errs, "llm.local_provider", cfg.LLM.LocalProvider, "ollama", "llamacpp")
	}
	if cfg.LLM.MinSeverityForLLM != "" {
		validateEnum(&errs, "llm.min_severity_llm", cfg.LLM.MinSeverityForLLM,
			"medium", "high", "critical")
	}
	if cfg.LLM.Enabled {
		validateMin(&errs, "llm.max_concurrent", cfg.LLM.MaxConcurrent, 1)
		validateMin(&errs, "llm.timeout_sec", cfg.LLM.TimeoutSec, 1)
	}

	if cfg.ML.RequireRuntime && !cfg.ML.Enabled {
		errs.add("ml.require_runtime is true but ml.enabled is false; enable ml or disable require_runtime")
	}
	if cfg.ML.Enabled {
		validateThreshold(&errs, "ml.thresholds.pe_malicious", cfg.ML.Thresholds.PEMalicious)
		validateThreshold(&errs, "ml.thresholds.behavior_anomaly", cfg.ML.Thresholds.BehaviorAnomaly)
		validateThreshold(&errs, "ml.thresholds.ransomware_score", cfg.ML.Thresholds.RansomwareScore)
		validateThreshold(&errs, "ml.thresholds.network_anomaly", cfg.ML.Thresholds.NetworkAnomaly)
	}
	if cfg.ML.Enabled && cfg.ML.RequireRuntime {
		if strings.TrimSpace(cfg.ML.ModelsDir) == "" {
			errs.add("ml.models_dir is required when ml.require_runtime is true")
		} else {
			validateDirExists(&errs, "ml.models_dir", cfg.ML.ModelsDir)
		}
	}

	if cfg.Detection.Behavioral.SensitivityLevel != "" {
		validateEnum(&errs, "detection.behavioral.sensitivity",
			cfg.Detection.Behavioral.SensitivityLevel,
			"low", "medium", "high", "paranoid")
	}
	if !cfg.Detection.Sigma.Enabled &&
		!cfg.Detection.YARA.Enabled &&
		!cfg.Detection.IOC.Enabled &&
		!cfg.ML.Enabled {
		errs.add("at least one detection layer must be enabled: sigma|yara|ioc|ml")
	}
	if cfg.Detection.YARA.RescanCooldownSec < 0 {
		errs.add("detection.yara.rescan_cooldown_sec must be >= 0, got %d", cfg.Detection.YARA.RescanCooldownSec)
	}
	if cfg.Detection.YARA.MaxScansPerMinute < 0 {
		errs.add("detection.yara.max_scans_per_minute must be >= 0, got %d", cfg.Detection.YARA.MaxScansPerMinute)
	}

	validateRange(&errs, "performance.max_cpu_percent", cfg.Performance.MaxCPUPercent, 1, 100)
	validateMin(&errs, "performance.max_memory_mb", cfg.Performance.MaxMemoryMB, 1)
	validateMin(&errs, "performance.event_buffer_size", cfg.Performance.EventBufferSize, 1)
	validateMin(&errs, "performance.worker_count", cfg.Performance.WorkerCount, 1)
	validateMin(&errs, "performance.batch_size", cfg.Performance.BatchSize, 1)
	validateMin(&errs, "performance.batch_interval_ms", cfg.Performance.BatchIntervalMs, 1)
	if cfg.Performance.Profile != "" {
		validateEnum(&errs, "performance.profile", cfg.Performance.Profile,
			"low_resource", "balanced", "strict")
	}
	if cfg.Logging.Mode != "" {
		validateEnum(&errs, "logging.mode", cfg.Logging.Mode,
			"structured", "pretty", "dual")
	}

	for i, feed := range cfg.ThreatIntel.CustomFeeds {
		if feed.Name == "" {
			errs.add("threat_intel.custom_feeds[%d].name is required", i)
		}
		if feed.URL == "" {
			errs.add("threat_intel.custom_feeds[%d].url is required", i)
		}
		if feed.Format != "" {
			validateEnum(&errs,
				fmt.Sprintf("threat_intel.custom_feeds[%d].format", i),
				feed.Format, "stix", "taxii", "csv", "json")
		}
	}

	if cfg.Forwarder.Enabled && cfg.Forwarder.Mode != "" {
		validateEnum(&errs, "forwarder.mode", cfg.Forwarder.Mode,
			"http", "syslog", "kafka")
	}

	if cfg.Monitoring.Mode != "" {
		validateEnum(&errs, "monitoring.mode", cfg.Monitoring.Mode,
			"auto", "userland", "kernel")
	}
	if cfg.Monitoring.ChecklistTier != "" {
		validateEnum(&errs, "monitoring.checklist_tier", cfg.Monitoring.ChecklistTier,
			"userland", "kernel_hooks", "full_edr")
	}
	if cfg.Monitoring.SecurityProfile != "" {
		validateEnum(&errs, "monitoring.security_profile", cfg.Monitoring.SecurityProfile,
			"standard", "regulated", "strict_complete")
	}
	if cfg.Monitoring.WindowsControlPlaneRequired &&
		!cfg.Monitoring.WindowsWFPCtlProbe &&
		strings.TrimSpace(cfg.Monitoring.WindowsMinifilterPort) == "" {
		errs.add("monitoring.windows_control_plane_required=true needs windows_wfp_ctl_probe=true or windows_minifilter_port set")
	}
	if cfg.Monitoring.WindowsControlPlaneRequired && !cfg.Monitoring.WindowsServiceHardening {
		errs.add("monitoring.windows_control_plane_required=true requires monitoring.windows_service_hardening=true (SCM posture)")
	}
	if cfg.Monitoring.WindowsServiceDaclHardened && !cfg.Monitoring.WindowsServiceHardening {
		errs.add("monitoring.windows_service_dacl_hardened=true requires monitoring.windows_service_hardening=true")
	}
	if cfg.Monitoring.WindowsPPLRequired {
		if !cfg.Monitoring.WindowsServiceHardening {
			errs.add("monitoring.windows_ppl_required=true requires monitoring.windows_service_hardening=true")
		}
		tier := strings.ToLower(strings.TrimSpace(cfg.Monitoring.WindowsServiceLaunchProtectedTier))
		if tier == "" && !cfg.Monitoring.WindowsServiceLaunchProtected {
			errs.add("monitoring.windows_ppl_required=true requires monitoring.windows_service_launch_protected_tier=antimalware_light")
		}
		if tier != "" && tier != "antimalware_light" && tier != "antimalware-light" && tier != "am-ppl" && tier != "ppl" && tier != "antimalware" {
			errs.add("monitoring.windows_ppl_required=true requires monitoring.windows_service_launch_protected_tier=antimalware_light (got %q)", tier)
		}
	}
	if tier := strings.ToLower(strings.TrimSpace(cfg.Monitoring.WindowsServiceLaunchProtectedTier)); tier != "" {
		switch tier {
		case "none", "off", "false", "0", "windows", "windows_light", "windows-light", "light", "antimalware", "antimalware_light", "antimalware-light", "am-ppl", "ppl":
		default:
			errs.add("monitoring.windows_service_launch_protected_tier must be none, windows_light, or antimalware_light (got %q)", tier)
		}
	}

	for i, lt := range cfg.Monitoring.LogTargets {
		t := strings.ToLower(strings.TrimSpace(lt.Type))
		validateEnum(&errs, fmt.Sprintf("monitoring.log_targets[%d].type", i), t,
			"file", "eventchannel", "journald", "command", "full_command")
		if strings.TrimSpace(lt.Path) == "" && t != "journald" {
			errs.add("monitoring.log_targets[%d].path is required for type %q", i, t)
		}
		if lt.Interval < 0 {
			errs.add("monitoring.log_targets[%d].interval must be >= 0", i)
		}
		if t == "eventchannel" && runtime.GOOS != "windows" {
			errs.add("monitoring.log_targets[%d].type=eventchannel requires windows", i)
		}
		if t == "journald" && runtime.GOOS != "linux" {
			errs.add("monitoring.log_targets[%d].type=journald requires linux", i)
		}
	}

	return errs.err()
}

func validateEnum(errs *ValidationErrors, field, value string, allowed ...string) {
	for _, a := range allowed {
		if value == a {
			return
		}
	}
	errs.add("%s must be one of %s, got %q", field, strings.Join(allowed, "|"), value)
}

func validateRange(errs *ValidationErrors, field string, value, min, max int) {
	if value < min || value > max {
		errs.add("%s must be %d–%d, got %d", field, min, max, value)
	}
}

func validateMin(errs *ValidationErrors, field string, value, min int) {
	if value < min {
		errs.add("%s must be >= %d, got %d", field, min, value)
	}
}

func validateThreshold(errs *ValidationErrors, field string, value float32) {
	if value < 0 || value > 1 {
		errs.add("%s must be 0.0–1.0, got %.2f", field, value)
	}
}

func validateFileReadable(errs *ValidationErrors, field, path string) {
	if strings.TrimSpace(path) == "" {
		errs.add("%s is required", field)
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		errs.add("%s not readable at %q: %v", field, path, err)
		return
	}
	if st.IsDir() {
		errs.add("%s must be a file, got directory %q", field, path)
	}
}

func validateDirExists(errs *ValidationErrors, field, path string) {
	if strings.TrimSpace(path) == "" {
		errs.add("%s is required", field)
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		errs.add("%s not accessible at %q: %v", field, path, err)
		return
	}
	if !st.IsDir() {
		errs.add("%s must be a directory, got file %q", field, path)
	}
}
