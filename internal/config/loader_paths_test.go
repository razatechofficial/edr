package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyResourcePathDefaultsComplianceSCA(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rulesRoot := filepath.Join(dir, "rules")
	scaDir := filepath.Join(rulesRoot, "compliance", "sca", "linux")
	if err := os.MkdirAll(scaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scaDir, "cis_test.yml"), []byte("policy:\n  id: test\nchecks: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config", "agent.yaml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("compliance:\n  enabled: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	cfg.Compliance.Enabled = true
	cfg.Compliance.RulesDir = ""
	applyResourcePathDefaults(&cfg, cfgPath)
	want := filepath.Join(filepath.Dir(cfgPath), "..", "rules", "compliance", "sca")
	want = filepath.Clean(want)
	if cfg.Compliance.RulesDir != want {
		t.Fatalf("rules_dir=%q want %q", cfg.Compliance.RulesDir, want)
	}
}
