package xdrclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	stateFileName = "enrollment.json"
	certFileName  = "agent.crt"
	keyFileName   = "agent.key"
	caFileName    = "ca-chain.pem"
)

// State is persisted after successful Register/Renew.
type State struct {
	AgentID        string    `json:"agent_id"`
	TenantID       string    `json:"tenant_id"`
	MachineID      string    `json:"machine_id"`
	CertificatePEM string    `json:"-"`
	CAChainPEM     []string  `json:"-"`
	IngestHosts    []string  `json:"ingest_hosts"`
	HeartbeatSec   int32     `json:"heartbeat_sec"`
	CertNotAfter   time.Time `json:"cert_not_after"`
	EnrolledAt     time.Time `json:"enrolled_at"`
	RenewedAt      time.Time `json:"renewed_at,omitempty"`
}

// Store persists enrollment material under CertDir.
type Store struct {
	Dir string
}

func (s Store) ensureDir() error {
	if strings.TrimSpace(s.Dir) == "" {
		return fmt.Errorf("xdr cert_dir is required")
	}
	return os.MkdirAll(s.Dir, 0o700)
}

func (s Store) statePath() string { return filepath.Join(s.Dir, stateFileName) }
func (s Store) certPath() string  { return filepath.Join(s.Dir, certFileName) }
func (s Store) keyPath() string   { return filepath.Join(s.Dir, keyFileName) }
func (s Store) caPath() string    { return filepath.Join(s.Dir, caFileName) }

// CertPath / KeyPath / CAPath expose PEM locations for mTLS dial.
func (s Store) CertPath() string { return s.certPath() }
func (s Store) KeyPath() string  { return s.keyPath() }
func (s Store) CAPath() string   { return s.caPath() }

// Save writes certs + metadata atomically.
func (s Store) Save(st State, keyPEM []byte) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	if err := os.WriteFile(s.certPath(), []byte(st.CertificatePEM), 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(s.keyPath(), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	var caBuf strings.Builder
	for _, pemBlock := range st.CAChainPEM {
		caBuf.WriteString(strings.TrimSpace(pemBlock))
		caBuf.WriteByte('\n')
	}
	if err := os.WriteFile(s.caPath(), []byte(caBuf.String()), 0o600); err != nil {
		return fmt.Errorf("write ca chain: %w", err)
	}
	meta, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statePath() + ".tmp"
	if err := os.WriteFile(tmp, meta, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath())
}

// Load reads enrollment metadata (certs stay on disk for tls.LoadX509KeyPair).
func (s Store) Load() (State, error) {
	data, err := os.ReadFile(s.statePath())
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, err
	}
	certPEM, err := os.ReadFile(s.certPath())
	if err != nil {
		return State{}, err
	}
	st.CertificatePEM = string(certPEM)
	return st, nil
}

// HasCredentials reports whether cert+key files exist.
func (s Store) HasCredentials() bool {
	_, errC := os.Stat(s.certPath())
	_, errK := os.Stat(s.keyPath())
	return errC == nil && errK == nil
}
