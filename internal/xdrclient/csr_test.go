package xdrclient_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/xdrclient"
)

func TestGenerateKeyAndCSRWithIdentity(t *testing.T) {
	k, err := xdrclient.GenerateKeyAndCSRWithIdentity(xdrclient.DeviceIdentity{
		AgentID:           "agent-123",
		Hostname:          "host.local",
		MachineID:         "machine-abc",
		OSFamily:          "darwin",
		OSVersion:         "arm64",
		AgentVer:          "1.0.0",
		Manufacturer:      "Apple",
		ProductModel:      "MacBookPro18,1",
		HardwareSerial:    "C02SERIAL01",
		PrimaryIP:         "192.168.1.10",
		Timezone:          "PKT",
		EnrollTimestamp:   "2026-07-14T07:00:00Z",
		EnrollmentTokenFP: "abcd1234ffff",
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(k.CSRPEM))
	if block == nil {
		t.Fatal("bad csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "agent-123" {
		t.Fatalf("cn=%s", csr.Subject.CommonName)
	}
	if csr.Subject.SerialNumber != "C02SERIAL01" {
		t.Fatalf("serial=%s", csr.Subject.SerialNumber)
	}
	if len(csr.Subject.Organization) == 0 || csr.Subject.Organization[0] != "Apple" {
		t.Fatalf("org=%v", csr.Subject.Organization)
	}
	joined := ""
	for _, u := range csr.URIs {
		joined += u.String() + " "
	}
	for _, want := range []string{
		"urn:xdr:agent:agent-123",
		"urn:xdr:hw-serial:C02SERIAL01",
		"urn:xdr:enrollment-token-fp:abcd1234ffff",
		"urn:xdr:ip:192.168.1.10",
		"urn:xdr:manufacturer:Apple",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
}

func TestStoreSaveLoadSealedKeyAndCert(t *testing.T) {
	dir := t.TempDir()
	dataDir := t.TempDir()
	store := xdrclient.Store{Dir: dir, DataDir: dataDir, Backend: "file"}
	k, err := xdrclient.GenerateKeyAndCSR("agent-abc")
	if err != nil {
		t.Fatal(err)
	}
	// Minimal self-signed-looking PEM is fine for seal roundtrip; use CSR pub as placeholder cert text.
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n"
	st := xdrclient.State{
		AgentID:        "agent-abc",
		MachineID:      "machine-1",
		CertificatePEM: certPEM,
		CAChainPEM:     []string{"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"},
		IngestHosts:    []string{"localhost:9020"},
		HeartbeatSec:   30,
		CertNotAfter:   time.Now().UTC().Add(24 * time.Hour),
		EnrolledAt:     time.Now().UTC(),
	}
	if err := store.SaveWithCSR(st, k.KeyPEM, k.CSRPEM); err != nil {
		t.Fatal(err)
	}
	if !store.HasCredentials() {
		t.Fatal("expected credentials")
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.key.enc")); err != nil {
		t.Fatal("expected sealed key")
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.crt.enc")); err != nil {
		t.Fatal("expected sealed cert")
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.csr.enc")); err != nil {
		t.Fatal("expected sealed csr")
	}
	for _, name := range []string{"agent.key", "agent.crt", "agent.csr"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("plaintext %s should not exist", name)
		}
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SecureStorage != "file" || loaded.CertificatePEM != certPEM {
		t.Fatalf("loaded=%+v", loaded)
	}
	csrOut, err := store.LoadCSRPEM()
	if err != nil || !strings.Contains(string(csrOut), "CERTIFICATE REQUEST") {
		t.Fatalf("csr load failed: %v %q", err, csrOut)
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
