//go:build windows

package xdrclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestInstallStagedIdentitySkipsWhenDPAPIExists(t *testing.T) {
	identityStageRoot = t.TempDir()
	t.Cleanup(func() {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		identityStageRoot = filepath.Join(pd, "EDR Agent")
	})

	data := t.TempDir()
	certDir := filepath.Join(data, "xdr-tls")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Has() only stats these names after DPAPI New() succeeds.
	if err := os.WriteFile(filepath.Join(certDir, "agent.key.dpapi"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "agent.crt.dpapi"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}

	stage := identityStageDir()
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "agent.key"), []byte("staged-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	yamlPath := filepath.Join(data, "config.yml")
	if err := os.WriteFile(yamlPath, []byte("xdr:\n  enabled: true\n  secure_storage: dpapi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.XDRConfig{CertDir: certDir, SecureStorage: "dpapi"}
	if err := InstallStagedIdentity(yamlPath, cfg, data); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stage, "agent.key")); !os.IsNotExist(err) {
		t.Fatal("identity-stage must be removed when DPAPI already has a cert")
	}
	raw, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secure_storage: file") {
		t.Fatalf("must not pin file backend:\n%s", raw)
	}
}
