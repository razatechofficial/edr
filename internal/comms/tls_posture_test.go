package comms

import (
	"strings"
	"testing"
)

// The control plane carries kill, isolate and quarantine commands, and the
// protocol has no message-level signature. A configuration that claims mutual
// TLS while presenting no client certificate leaves an operator believing the
// channel is mutually authenticated when it is not.
func TestMutualTLSWithoutACertificateIsRefusedNotDowngraded(t *testing.T) {
	_, err := LoadTLSConfig("", "", "", true)
	if err == nil {
		t.Fatal("mutual_tls with no certificate was accepted")
	}
	if !strings.Contains(err.Error(), "mutual_tls") {
		t.Errorf("err = %v; want it to name the setting at fault", err)
	}

	// Half a pair is still no pair.
	if _, err := LoadTLSConfig("/nonexistent.crt", "", "", true); err == nil {
		t.Error("mutual_tls with only a certificate path was accepted")
	}
	if _, err := LoadTLSConfig("", "/nonexistent.key", "", true); err == nil {
		t.Error("mutual_tls with only a key path was accepted")
	}
}

// Server-authenticated TLS remains available for deployments that have not
// issued client certificates — it just has to be asked for honestly.
func TestServerAuthenticatedTLSIsStillAvailable(t *testing.T) {
	cfg, err := LoadTLSConfig("", "", "", false)
	if err != nil {
		t.Fatalf("server-authenticated TLS was refused: %v", err)
	}
	if cfg == nil {
		t.Fatal("no TLS configuration returned")
	}
	if len(cfg.Certificates) != 0 {
		t.Error("a client certificate was presented without mutual_tls")
	}
	if cfg.MinVersion < 0x0303 {
		t.Errorf("MinVersion = %x, want TLS 1.2 or above", cfg.MinVersion)
	}
}
