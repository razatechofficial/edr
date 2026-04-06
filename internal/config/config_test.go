package config

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDefaults(t *testing.T) {
	t.Parallel()
	cfg := Defaults()

	if cfg.Agent.LogLevel != "info" {
		t.Errorf("Agent.LogLevel = %q, want %q", cfg.Agent.LogLevel, "info")
	}
	if cfg.Agent.DataDir != "/var/lib/edr" {
		t.Errorf("Agent.DataDir = %q, want %q", cfg.Agent.DataDir, "/var/lib/edr")
	}
	if cfg.Agent.TempDir != "/tmp/edr" {
		t.Errorf("Agent.TempDir = %q, want %q", cfg.Agent.TempDir, "/tmp/edr")
	}

	if cfg.Server.GRPCPort != 50051 {
		t.Errorf("Server.GRPCPort = %d, want %d", cfg.Server.GRPCPort, 50051)
	}
	if cfg.Server.HeartbeatSec != 30 {
		t.Errorf("Server.HeartbeatSec = %d, want %d", cfg.Server.HeartbeatSec, 30)
	}
	if cfg.Server.ReconnectSec != 5 {
		t.Errorf("Server.ReconnectSec = %d, want %d", cfg.Server.ReconnectSec, 5)
	}
	if !cfg.Server.MutualTLS {
		t.Error("Server.MutualTLS should be true")
	}

	if cfg.LLM.PrimaryProvider != "grok" {
		t.Errorf("LLM.PrimaryProvider = %q, want %q", cfg.LLM.PrimaryProvider, "grok")
	}
	if cfg.LLM.LocalProvider != "ollama" {
		t.Errorf("LLM.LocalProvider = %q, want %q", cfg.LLM.LocalProvider, "ollama")
	}
	if cfg.LLM.MinSeverityForLLM != "medium" {
		t.Errorf("LLM.MinSeverityForLLM = %q, want %q", cfg.LLM.MinSeverityForLLM, "medium")
	}
	if cfg.LLM.MaxConcurrent != 4 {
		t.Errorf("LLM.MaxConcurrent = %d, want %d", cfg.LLM.MaxConcurrent, 4)
	}
	if cfg.LLM.TimeoutSec != 30 {
		t.Errorf("LLM.TimeoutSec = %d, want %d", cfg.LLM.TimeoutSec, 30)
	}
	if cfg.LLM.Grok.BaseURL != "https://api.x.ai/v1" {
		t.Errorf("LLM.Grok.BaseURL = %q, want %q", cfg.LLM.Grok.BaseURL, "https://api.x.ai/v1")
	}
	if cfg.LLM.Ollama.Endpoint != "http://localhost:11434" {
		t.Errorf("LLM.Ollama.Endpoint = %q, want %q", cfg.LLM.Ollama.Endpoint, "http://localhost:11434")
	}

	if cfg.ML.Thresholds.PEMalicious != 0.80 {
		t.Errorf("ML.Thresholds.PEMalicious = %f, want %f", cfg.ML.Thresholds.PEMalicious, 0.80)
	}
	if cfg.ML.Thresholds.BehaviorAnomaly != 0.75 {
		t.Errorf("ML.Thresholds.BehaviorAnomaly = %f, want %f", cfg.ML.Thresholds.BehaviorAnomaly, 0.75)
	}
	if cfg.ML.Thresholds.RansomwareScore != 0.85 {
		t.Errorf("ML.Thresholds.RansomwareScore = %f, want %f", cfg.ML.Thresholds.RansomwareScore, 0.85)
	}
	if cfg.ML.Thresholds.NetworkAnomaly != 0.70 {
		t.Errorf("ML.Thresholds.NetworkAnomaly = %f, want %f", cfg.ML.Thresholds.NetworkAnomaly, 0.70)
	}

	if !cfg.Detection.Sigma.Enabled {
		t.Error("Detection.Sigma.Enabled should be true")
	}
	if !cfg.Detection.YARA.Enabled {
		t.Error("Detection.YARA.Enabled should be true")
	}
	if !cfg.Detection.IOC.Enabled {
		t.Error("Detection.IOC.Enabled should be true")
	}
	if cfg.Detection.Behavioral.BaselineDays != 7 {
		t.Errorf("Detection.Behavioral.BaselineDays = %d, want %d", cfg.Detection.Behavioral.BaselineDays, 7)
	}
	if cfg.Detection.Behavioral.SensitivityLevel != "high" {
		t.Errorf("Detection.Behavioral.SensitivityLevel = %q, want %q", cfg.Detection.Behavioral.SensitivityLevel, "high")
	}
	if !cfg.Detection.Behavioral.RansomwareDetect {
		t.Error("Detection.Behavioral.RansomwareDetect should be true")
	}
	if !cfg.Detection.Behavioral.RATDetect {
		t.Error("Detection.Behavioral.RATDetect should be true")
	}
	if !cfg.Detection.Behavioral.ExfilDetect {
		t.Error("Detection.Behavioral.ExfilDetect should be true")
	}
	if !cfg.Detection.Behavioral.LateralDetect {
		t.Error("Detection.Behavioral.LateralDetect should be true")
	}

	if cfg.Performance.MaxCPUPercent != 5 {
		t.Errorf("Performance.MaxCPUPercent = %d, want %d", cfg.Performance.MaxCPUPercent, 5)
	}
	if cfg.Performance.MaxMemoryMB != 200 {
		t.Errorf("Performance.MaxMemoryMB = %d, want %d", cfg.Performance.MaxMemoryMB, 200)
	}
	if cfg.Performance.EventBufferSize != 65536 {
		t.Errorf("Performance.EventBufferSize = %d, want %d", cfg.Performance.EventBufferSize, 65536)
	}
	if cfg.Performance.WorkerCount != runtime.NumCPU() {
		t.Errorf("Performance.WorkerCount = %d, want %d", cfg.Performance.WorkerCount, runtime.NumCPU())
	}
	if cfg.Performance.BatchSize != 50 {
		t.Errorf("Performance.BatchSize = %d, want %d", cfg.Performance.BatchSize, 50)
	}
	if cfg.Performance.BatchIntervalMs != 15000 {
		t.Errorf("Performance.BatchIntervalMs = %d, want %d", cfg.Performance.BatchIntervalMs, 15000)
	}

	if cfg.Service.TickInterval != time.Second {
		t.Errorf("Service.TickInterval = %v, want %v", cfg.Service.TickInterval, time.Second)
	}
	if cfg.LegacyResponse.MinKillScore != 90 {
		t.Errorf("LegacyResponse.MinKillScore = %d, want %d", cfg.LegacyResponse.MinKillScore, 90)
	}
	if cfg.RulesFile != "rules/baseline.yaml" {
		t.Errorf("RulesFile = %q, want %q", cfg.RulesFile, "rules/baseline.yaml")
	}
}

func TestLoadYAML(t *testing.T) {
	cfg, err := Load("../../configs/agent.example.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Service.EndpointID != "host-dev-01" {
		t.Errorf("Service.EndpointID = %q, want %q", cfg.Service.EndpointID, "host-dev-01")
	}
	if cfg.RulesFile != "rules/baseline.yaml" {
		t.Errorf("RulesFile = %q, want %q", cfg.RulesFile, "rules/baseline.yaml")
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "info")
	}
	if cfg.Logging.AlertFile != "./alerts/alerts.jsonl" {
		t.Errorf("Logging.AlertFile = %q, want %q", cfg.Logging.AlertFile, "./alerts/alerts.jsonl")
	}
	if cfg.Service.PIDFile != "./alerts/agent.pid" {
		t.Errorf("Service.PIDFile = %q, want %q", cfg.Service.PIDFile, "./alerts/agent.pid")
	}
	if !cfg.LegacyResponse.AllowKill {
		t.Error("LegacyResponse.AllowKill should be true from YAML")
	}
	if cfg.LegacyResponse.MinKillScore != 90 {
		t.Errorf("LegacyResponse.MinKillScore = %d, want %d", cfg.LegacyResponse.MinKillScore, 90)
	}
	if cfg.Forwarder.Mode != "http" {
		t.Errorf("Forwarder.Mode = %q, want %q", cfg.Forwarder.Mode, "http")
	}
	if cfg.Agent.ID == "" {
		t.Error("Agent.ID should be auto-generated by validation")
	}
}

func TestLoadWithEnvOverride(t *testing.T) {
	t.Setenv("AGENT_ID", "test-agent-override")
	t.Setenv("LOG_LEVEL", "debug")

	cfg, err := Load("../../configs/agent.example.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.ID != "test-agent-override" {
		t.Errorf("Agent.ID = %q, want %q", cfg.Agent.ID, "test-agent-override")
	}
	if cfg.Agent.LogLevel != "debug" {
		t.Errorf("Agent.LogLevel = %q, want %q", cfg.Agent.LogLevel, "debug")
	}
}

func TestValidateValidConfig(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Agent.ID = "preset-agent-id"
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateInvalidLogLevel(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Agent.ID = "test"
	cfg.Agent.LogLevel = "INVALID"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected validation error for invalid log level")
	}
	ve, ok := err.(*ValidationErrors)
	if !ok {
		t.Fatalf("expected *ValidationErrors, got %T", err)
	}
	found := false
	for _, e := range ve.Errors {
		if contains(e, "agent.log_level") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about agent.log_level, got: %v", ve.Errors)
	}
}

func TestValidateInvalidPort(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Agent.ID = "test"
	cfg.Server.GRPCPort = 70000

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected validation error for out-of-range port")
	}
	ve, ok := err.(*ValidationErrors)
	if !ok {
		t.Fatalf("expected *ValidationErrors, got %T", err)
	}
	found := false
	for _, e := range ve.Errors {
		if contains(e, "server.grpc_port") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about server.grpc_port, got: %v", ve.Errors)
	}
}

func TestValidateInvalidProvider(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Agent.ID = "test"
	cfg.LLM.PrimaryProvider = "nonexistent_provider"

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected validation error for invalid LLM provider")
	}
	ve, ok := err.(*ValidationErrors)
	if !ok {
		t.Fatalf("expected *ValidationErrors, got %T", err)
	}
	found := false
	for _, e := range ve.Errors {
		if contains(e, "llm.primary_provider") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about llm.primary_provider, got: %v", ve.Errors)
	}
}

func TestValidateAutoGeneratesAgentID(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Agent.ID = ""

	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.Agent.ID == "" {
		t.Fatal("Agent.ID should be auto-generated when empty")
	}
	if _, err := uuid.Parse(cfg.Agent.ID); err != nil {
		t.Errorf("Agent.ID %q is not a valid UUID: %v", cfg.Agent.ID, err)
	}
}

func TestValidateMultiError(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Agent.ID = "keep-this"
	cfg.Agent.LogLevel = "INVALID"
	cfg.LLM.PrimaryProvider = "bad_provider"
	cfg.Performance.MaxCPUPercent = 200

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("expected validation errors")
	}
	ve, ok := err.(*ValidationErrors)
	if !ok {
		t.Fatalf("expected *ValidationErrors, got %T", err)
	}
	if len(ve.Errors) < 3 {
		t.Errorf("expected at least 3 errors, got %d: %v", len(ve.Errors), ve.Errors)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// suppress unused import warning
var _ = os.Getenv
