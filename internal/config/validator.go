package config

import (
	"fmt"
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

	llmProviders := []string{
		"openai", "anthropic", "grok", "gemini",
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

	if cfg.ML.Enabled {
		validateThreshold(&errs, "ml.thresholds.pe_malicious", cfg.ML.Thresholds.PEMalicious)
		validateThreshold(&errs, "ml.thresholds.behavior_anomaly", cfg.ML.Thresholds.BehaviorAnomaly)
		validateThreshold(&errs, "ml.thresholds.ransomware_score", cfg.ML.Thresholds.RansomwareScore)
		validateThreshold(&errs, "ml.thresholds.network_anomaly", cfg.ML.Thresholds.NetworkAnomaly)
	}

	if cfg.Detection.Behavioral.SensitivityLevel != "" {
		validateEnum(&errs, "detection.behavioral.sensitivity",
			cfg.Detection.Behavioral.SensitivityLevel,
			"low", "medium", "high", "paranoid")
	}

	validateRange(&errs, "performance.max_cpu_percent", cfg.Performance.MaxCPUPercent, 1, 100)
	validateMin(&errs, "performance.max_memory_mb", cfg.Performance.MaxMemoryMB, 1)
	validateMin(&errs, "performance.event_buffer_size", cfg.Performance.EventBufferSize, 1)
	validateMin(&errs, "performance.worker_count", cfg.Performance.WorkerCount, 1)
	validateMin(&errs, "performance.batch_size", cfg.Performance.BatchSize, 1)
	validateMin(&errs, "performance.batch_interval_ms", cfg.Performance.BatchIntervalMs, 1)

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
