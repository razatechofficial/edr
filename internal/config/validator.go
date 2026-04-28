package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
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
		cfg.Agent.ID = uuid.New().String()
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
	if cfg.Server.MutualTLS && (cfg.Server.TLSCertPath != "" || cfg.Server.TLSKeyPath != "") {
		validateFileReadable(&errs, "server.tls_cert", cfg.Server.TLSCertPath)
		validateFileReadable(&errs, "server.tls_key", cfg.Server.TLSKeyPath)
	}
	if cfg.Server.CACertPath != "" {
		validateFileReadable(&errs, "server.ca_cert", cfg.Server.CACertPath)
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
	if cfg.ML.Enabled && cfg.ML.ModelsDir != "" {
		validateDirExists(&errs, "ml.models_dir", cfg.ML.ModelsDir)
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
