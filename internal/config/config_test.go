package config

import "testing"

func TestLoadConfig(t *testing.T) {
	cfg, err := Load("../../configs/agent.example.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Service.EndpointID == "" {
		t.Fatal("endpoint id should not be empty")
	}
	if cfg.RulesFile == "" {
		t.Fatal("rules file should not be empty")
	}
}
