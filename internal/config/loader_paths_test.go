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

func TestApplyResourcePathDefaultsIOC(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	iocDir := filepath.Join(dir, "rules", "ioc")
	if err := os.MkdirAll(iocDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"hashes.json":  `[{"hash":"abc","type":"sha256"}]`,
		"ips.csv":      "address,cidr,reputation,source,severity,country,asn,tags\n",
		"domains.csv":  "domain,is_wildcard,reputation,source,severity,category,tags\n",
	} {
		if err := os.WriteFile(filepath.Join(iocDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(dir, "config", "agent.yaml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("detection:\n  ioc:\n    enabled: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	cfg.Detection.IOC.Enabled = true
	applyResourcePathDefaults(&cfg, cfgPath)
	wantRoot := filepath.Clean(filepath.Join(filepath.Dir(cfgPath), "..", "rules", "ioc"))
	if cfg.Detection.IOC.HashDBPath != filepath.Join(wantRoot, "hashes.json") {
		t.Fatalf("hash_db_path=%q", cfg.Detection.IOC.HashDBPath)
	}
	if cfg.Detection.IOC.IPDBPath != filepath.Join(wantRoot, "ips.csv") {
		t.Fatalf("ip_db_path=%q", cfg.Detection.IOC.IPDBPath)
	}
	if cfg.Detection.IOC.DomainDBPath != filepath.Join(wantRoot, "domains.csv") {
		t.Fatalf("domain_db_path=%q", cfg.Detection.IOC.DomainDBPath)
	}
}
