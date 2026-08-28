package xdrclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestStageAndInstallIdentity(t *testing.T) {
	identityStageRoot = t.TempDir()
	t.Cleanup(func() { identityStageRoot = "/tmp" })

	data := t.TempDir()
	certDir := filepath.Join(data, "xdr-tls")
	src := Store{Dir: certDir, DataDir: data, Backend: "file"}
	st := State{
		AgentID:        "agent-1",
		MachineID:      "mid-1",
		IngestHosts:    []string{"ingest.example:443"},
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
	}
	key := []byte("-----BEGIN EC PRIVATE KEY-----\nTESTKEY\n-----END EC PRIVATE KEY-----\n")
	if err := src.SaveWithCSR(st, key, ""); err != nil {
		t.Fatal(err)
	}

	cfg := config.XDRConfig{CertDir: certDir, SecureStorage: "file"}
	if err := StageIdentityFromLocalKeystore(cfg, data); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(identityStageDir(), "agent.key")); err != nil {
		t.Fatal(err)
	}

	installed := t.TempDir()
	dstCert := filepath.Join(installed, "xdr-tls")
	yamlPath := filepath.Join(installed, "agent.yaml")
	if err := os.WriteFile(yamlPath, []byte("agent:\n  id: a1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dstCfg := config.XDRConfig{CertDir: dstCert, SecureStorage: "file"}
	if err := InstallStagedIdentity(yamlPath, dstCfg, installed); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, "enabled: true") || !strings.Contains(body, "ingest.example:443") {
		t.Fatalf("expected ingest yaml, got:\n%s", body)
	}
	got, err := (Store{Dir: dstCert, DataDir: installed, Backend: "file"}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentID != "agent-1" {
		t.Fatalf("agent_id=%s", got.AgentID)
	}
}

func TestStageIdentitySkipsDaemonOwnedBlobs(t *testing.T) {
	identityStageRoot = t.TempDir()
	t.Cleanup(func() { identityStageRoot = "/tmp" })

	data := t.TempDir()
	certDir := filepath.Join(data, "xdr-tls")
	src := Store{Dir: certDir, DataDir: data, Backend: "file"}
	st := State{
		AgentID:        "agent-1",
		MachineID:      "mid-1",
		IngestHosts:    []string{"ingest.example:443"},
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
	}
	key := []byte("-----BEGIN EC PRIVATE KEY-----\nTESTKEY\n-----END EC PRIVATE KEY-----\n")
	if err := src.SaveWithCSR(st, key, ""); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"agent.crt.enc", "agent.key.enc", "agent.csr.enc"} {
		p := filepath.Join(certDir, name)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, name := range []string{"agent.crt.enc", "agent.key.enc", "agent.csr.enc"} {
			_ = os.Chmod(filepath.Join(certDir, name), 0o600)
		}
	})
	cfg := config.XDRConfig{CertDir: certDir, SecureStorage: "file"}
	if err := StageIdentityFromLocalKeystore(cfg, data); err != nil {
		t.Fatalf("daemon-owned identity should not fail stage: %v", err)
	}
}
