package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestEnsureAgentIdentityPersists(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := Defaults()
	cfg.Agent.DataDir = dir

	if err := EnsureAgentIdentity(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.ID == "" {
		t.Fatal("expected generated agent id")
	}
	if _, err := uuid.Parse(cfg.Agent.ID); err != nil {
		t.Fatalf("invalid uuid: %v", err)
	}

	cfg2 := Defaults()
	cfg2.Agent.DataDir = dir
	if err := EnsureAgentIdentity(&cfg2); err != nil {
		t.Fatal(err)
	}
	if cfg2.Agent.ID != cfg.Agent.ID {
		t.Fatalf("agent id changed: %q -> %q", cfg.Agent.ID, cfg2.Agent.ID)
	}
}

func TestNormalizeServerEndpoint(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Server.Endpoint = "mgr.example.com:50052"
	cfg.Server.GRPCPort = 0
	NormalizeServerEndpoint(&cfg)
	if cfg.Server.Endpoint != "mgr.example.com" {
		t.Fatalf("endpoint = %q", cfg.Server.Endpoint)
	}
	if cfg.Server.GRPCPort != 50052 {
		t.Fatalf("grpc_port = %d", cfg.Server.GRPCPort)
	}
}

func TestValidateRequiresAgentID(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := Defaults()
	cfg.Agent.DataDir = dir
	if err := EnsureAgentIdentity(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	idPath := filepath.Join(dir, agentIDFileName)
	if _, err := os.Stat(idPath); err != nil {
		t.Fatalf("agent_id file missing: %v", err)
	}
}
