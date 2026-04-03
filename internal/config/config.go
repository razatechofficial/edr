package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Service struct {
		EndpointID   string        `yaml:"endpoint_id"`
		TickInterval time.Duration `yaml:"tick_interval"`
		PIDFile      string        `yaml:"pid_file"`
	} `yaml:"service"`
	Logging struct {
		Level     string `yaml:"level"`
		AlertFile string `yaml:"alert_file"`
		AuditFile string `yaml:"audit_file"`
	} `yaml:"logging"`
	Response struct {
		AllowKill          bool     `yaml:"allow_kill"`
		AutoKillEnabled    bool     `yaml:"auto_kill_enabled"`
		MinKillScore       int      `yaml:"min_kill_score"`
		KillRuleAllowlist  []string `yaml:"kill_rule_allowlist"`
		ProtectedProcesses []string `yaml:"protected_processes"`
	} `yaml:"response"`
	Forwarder struct {
		Enabled  bool   `yaml:"enabled"`
		Mode     string `yaml:"mode"`
		Endpoint string `yaml:"endpoint"`
	} `yaml:"forwarder"`
	RulesFile string `yaml:"rules_file"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Service.TickInterval <= 0 {
		cfg.Service.TickInterval = time.Second
	}
	if cfg.RulesFile == "" {
		cfg.RulesFile = "rules/baseline.yaml"
	}
	if cfg.Response.MinKillScore <= 0 {
		cfg.Response.MinKillScore = 90
	}
	return cfg, nil
}
