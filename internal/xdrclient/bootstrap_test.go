package xdrclient_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func TestApplyBootstrapTokenFile(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "enrollment.token")
	if err := os.WriteFile(tokenPath, []byte("  secret-token-xyz  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.XDRConfig{EnrollmentHost: "enroll.example:50051"}
	res, err := xdrclient.ApplyBootstrap(&cfg, xdrclient.BootstrapOverrides{ConfigDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TokenFromFile || cfg.EnrollmentToken != "secret-token-xyz" {
		t.Fatalf("got token=%q fromFile=%v path=%s", cfg.EnrollmentToken, res.TokenFromFile, res.TokenFileUsed)
	}
	if !cfg.HasBootstrapCredentials() {
		t.Fatal("expected bootstrap credentials")
	}
}

func TestClearEnrollmentTokenInConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	raw := "agent:\n  id: a1\nxdr:\n  enabled: true\n  enrollment_host: h:1\n  enrollment_token: KEEP_SECRET\n"
	if err := os.WriteFile(path, []byte(raw), 0o640); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "enrollment.token")
	if err := os.WriteFile(tokenFile, []byte("KEEP_SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := xdrclient.ClearBootstrapMaterial(path, tokenFile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Fatal("token file should be removed")
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "KEEP_SECRET") {
		t.Fatalf("token still in config: %s", out)
	}
}

func TestPatchXDRConfigFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("agent:\n  id: a1\n  data_dir: "+dir+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := xdrclient.PatchXDRConfigFile(path, "enroll:50051", true); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.XDR.Enabled || cfg.XDR.EnrollmentHost != "enroll:50051" || !cfg.XDR.InsecureSkipTLS {
		t.Fatalf("xdr=%+v", cfg.XDR)
	}
	if cfg.XDR.EnrollmentToken != "" {
		t.Fatal("token must not be embedded in yaml")
	}
}

func TestPatchXDRConfigFileProdHostSetsIngest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("agent:\n  id: a1\n  data_dir: "+dir+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := xdrclient.PatchXDRConfigFile(path, xdrclient.DefaultEnrollmentHost, false); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.XDR.InsecureSkipTLS {
		t.Fatal("prod install must not skip TLS")
	}
	if len(cfg.XDR.IngestHosts) != 1 || cfg.XDR.IngestHosts[0] != xdrclient.DefaultIngestHost {
		t.Fatalf("ingest_hosts=%v", cfg.XDR.IngestHosts)
	}
}

func TestEnableIngestFromEnrollmentCreatesSection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("agent:\n  id: a1\n  data_dir: "+dir+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	st := xdrclient.State{
		IngestHosts:   []string{"ingest.xdr.averox.com:443"},
		SecureStorage: "keychain",
	}
	if err := xdrclient.EnableIngestFromEnrollment(path, st); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.XDR.Enabled {
		t.Fatal("expected xdr.enabled")
	}
	if cfg.XDR.EnrollmentHost != xdrclient.DefaultEnrollmentHost {
		t.Fatalf("enrollment_host=%s", cfg.XDR.EnrollmentHost)
	}
	if cfg.XDR.SecureStorage != "file" {
		t.Fatalf("secure_storage=%s want file", cfg.XDR.SecureStorage)
	}
	if len(cfg.XDR.IngestHosts) != 1 || cfg.XDR.IngestHosts[0] != "ingest.xdr.averox.com:443" {
		t.Fatalf("ingest_hosts=%v", cfg.XDR.IngestHosts)
	}
	if cfg.XDR.EnrollmentToken != "" {
		t.Fatal("token must not be embedded")
	}
	envRaw, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	envBody := string(envRaw)
	if !strings.Contains(envBody, "XDR_ENABLED=true") || !strings.Contains(envBody, "XDR_SECURE_STORAGE=file") {
		t.Fatalf("runtime env=%s", envBody)
	}
}
