package xdrclient_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/xdrclient"
)

func TestGenerateKeyAndCSR(t *testing.T) {
	k, err := xdrclient.GenerateKeyAndCSR("agent-123")
	if err != nil {
		t.Fatal(err)
	}
	if k.CSRPEM == "" || len(k.KeyPEM) == 0 {
		t.Fatal("empty csr or key")
	}
	if !strings.Contains(k.CSRPEM, "CERTIFICATE REQUEST") {
		t.Fatalf("unexpected csr pem")
	}
}

func TestStoreSaveLoad(t *testing.T) {
	dir := t.TempDir()
	store := xdrclient.Store{Dir: dir}
	k, err := xdrclient.GenerateKeyAndCSR("agent-abc")
	if err != nil {
		t.Fatal(err)
	}
	st := xdrclient.State{
		AgentID:        "agent-abc",
		TenantID:       "tenant-1",
		MachineID:      "machine-1",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		CAChainPEM:     []string{"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"},
		IngestHosts:    []string{"localhost:50052"},
		HeartbeatSec:   30,
		CertNotAfter:   time.Now().UTC().Add(24 * time.Hour),
		EnrolledAt:     time.Now().UTC(),
	}
	if err := store.Save(st, k.KeyPEM); err != nil {
		t.Fatal(err)
	}
	if !store.HasCredentials() {
		t.Fatal("expected credentials on disk")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AgentID != "agent-abc" || loaded.TenantID != "tenant-1" {
		t.Fatalf("loaded = %+v", loaded)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.key")); err != nil {
		t.Fatal(err)
	}
}

func TestNeedsRenew(t *testing.T) {
	soon := time.Now().UTC().Add(3 * 24 * time.Hour)
	if !xdrclient.NeedsRenew(soon, 7) {
		t.Fatal("expected renew when within 7 days")
	}
	later := time.Now().UTC().Add(30 * 24 * time.Hour)
	if xdrclient.NeedsRenew(later, 7) {
		t.Fatal("did not expect renew")
	}
}
