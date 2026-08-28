package xdrclient

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/xdrclient/keystore"
)

const (
	stateFileName     = "enrollment.json"
	caFileName        = "ca-chain.pem"
	ingestSeqFileName = "ingest.seq"
)

// State is persisted after successful Register/Renew.
type State struct {
	AgentID        string    `json:"agent_id"`
	MachineID      string    `json:"machine_id"`
	CertificatePEM string    `json:"-"`
	CAChainPEM     []string  `json:"-"`
	IngestHosts    []string  `json:"ingest_hosts"`
	HeartbeatSec   int32     `json:"heartbeat_sec"`
	CertNotAfter   time.Time `json:"cert_not_after"`
	EnrolledAt     time.Time `json:"enrolled_at"`
	RenewedAt      time.Time `json:"renewed_at,omitempty"`
	SecureStorage  string    `json:"secure_storage,omitempty"` // keychain|dpapi|file
	// LastIngestSeq is the last StreamTelemetry sequence ACK'd by ingest.
	LastIngestSeq int64 `json:"last_ingest_seq,omitempty"`
}

// Store persists enrollment material. Private key + cert (+ CSR) go to an
// OS-backed keystore when available; CA chain and metadata stay on disk.
type Store struct {
	Dir     string
	DataDir string
	Backend string // auto|keychain|dpapi|file
}

func (s Store) openKS() (keystore.Store, error) {
	return keystore.New(keystore.Options{
		Backend: s.Backend,
		Dir:     s.Dir,
		DataDir: s.DataDir,
	})
}

func (s Store) ensureDir() error {
	if strings.TrimSpace(s.Dir) == "" {
		return fmt.Errorf("xdr cert_dir is required")
	}
	return os.MkdirAll(s.Dir, 0o755)
}

func (s Store) statePath() string { return filepath.Join(s.Dir, stateFileName) }
func (s Store) caPath() string    { return filepath.Join(s.Dir, caFileName) }

// CertPath / KeyPath / CAPath expose diagnostic paths (file backend / CA only).
func (s Store) CertPath() string { return filepath.Join(s.Dir, "agent.crt") }
func (s Store) KeyPath() string  { return filepath.Join(s.Dir, "agent.key") }
func (s Store) CAPath() string   { return s.caPath() }

func (s Store) encKeyPath() string  { return filepath.Join(s.Dir, "agent.key.enc") }
func (s Store) encCertPath() string { return filepath.Join(s.Dir, "agent.crt.enc") }
func (s Store) encCSRPath() string  { return filepath.Join(s.Dir, "agent.csr.enc") }
func (s Store) csrPath() string     { return filepath.Join(s.Dir, "agent.csr") }

// BackendName returns the resolved secure-storage backend.
func (s Store) BackendName() string {
	ks, err := s.openKS()
	if err != nil {
		return keystore.BackendFile
	}
	return ks.Name()
}

// Save writes sealed/OS-stored key + cert + metadata.
func (s Store) Save(st State, keyPEM []byte) error {
	return s.SaveWithCSR(st, keyPEM, "")
}

// SaveWithCSR persists identity material via OS keystore + metadata/CA on disk.
func (s Store) SaveWithCSR(st State, keyPEM []byte, csrPEM string) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	ks, err := s.openKS()
	if err != nil {
		return err
	}
	if err := ks.Save(keystore.Material{
		KeyPEM:  keyPEM,
		CertPEM: []byte(st.CertificatePEM),
		CSRPEM:  []byte(strings.TrimSpace(csrPEM)),
	}); err != nil {
		return fmt.Errorf("secure store save (%s): %w", ks.Name(), err)
	}

	var caBuf strings.Builder
	for _, pemBlock := range st.CAChainPEM {
		caBuf.WriteString(strings.TrimSpace(pemBlock))
		caBuf.WriteByte('\n')
	}
	if caBuf.Len() > 0 {
		if err := os.WriteFile(s.caPath(), []byte(caBuf.String()), 0o600); err != nil {
			return fmt.Errorf("write ca chain: %w", err)
		}
	}
	st.SecureStorage = ks.Name()
	return s.persistMetadata(st)
}

// LoadPrivateKeyPEM returns the on-device private key (into memory only).
func (s Store) LoadPrivateKeyPEM() ([]byte, error) {
	ks, err := s.openKS()
	if err != nil {
		return nil, err
	}
	return ks.LoadKeyPEM()
}

// LoadCertificatePEM returns the signed cert (into memory only).
func (s Store) LoadCertificatePEM() ([]byte, error) {
	ks, err := s.openKS()
	if err != nil {
		return nil, err
	}
	return ks.LoadCertPEM()
}

// LoadCSRPEM returns the enrollment CSR if present.
func (s Store) LoadCSRPEM() ([]byte, error) {
	ks, err := s.openKS()
	if err != nil {
		return nil, err
	}
	return ks.LoadCSRPEM()
}

// Load reads enrollment metadata and certificate PEM.
func (s Store) Load() (State, error) {
	data, err := os.ReadFile(s.statePath())
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, err
	}
	certPEM, err := s.LoadCertificatePEM()
	if err != nil {
		return State{}, err
	}
	st.CertificatePEM = string(certPEM)
	if st.SecureStorage == "" {
		st.SecureStorage = s.BackendName()
	}
	return st, nil
}

// SaveMetadata rewrites enrollment.json (+ backend name) without rotating key/cert.
// Used when secure store already holds identity but the sidecar metadata was lost.
func (s Store) SaveMetadata(st State) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	st.SecureStorage = s.BackendName()
	return s.persistMetadata(st)
}

// persistMetadata writes enrollment.json so the local console user can read
// identity fields (no private key). Ingest hosts stay on disk for the sensor.
func (s Store) persistMetadata(st State) error {
	meta, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statePath() + ".tmp"
	if err := os.WriteFile(tmp, meta, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.statePath()); err != nil {
		return err
	}
	s.relaxIdentityPerms()
	return os.Chmod(s.statePath(), 0o644)
}

// RebindDaemonReadable rewrites key+cert+metadata so the machine-wide sensor
// can load identity (System keychain + sealed files, world-readable sidecar).
func (s Store) RebindDaemonReadable(st State) error {
	key, err := s.LoadPrivateKeyPEM()
	if err != nil {
		return err
	}
	csr, _ := s.LoadCSRPEM()
	return s.SaveWithCSR(st, key, string(csr))
}

// relaxIdentityPerms lets the local console user read enrollment.json.
// Private key/cert blobs stay 0600; only the directory and metadata open up.
func (s Store) relaxIdentityPerms() {
	if strings.TrimSpace(s.DataDir) != "" {
		_ = os.Chmod(s.DataDir, 0o755)
		_ = os.Chmod(filepath.Join(s.DataDir, "agent_id"), 0o644)
	}
	_ = os.Chmod(s.Dir, 0o755)
}

// LoadCAChainPEM reads the on-disk CA chain when present.
func (s Store) LoadCAChainPEM() []string {
	data, err := os.ReadFile(s.caPath())
	if err != nil || len(data) == 0 {
		return nil
	}
	var out []string
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, string(pem.EncodeToMemory(block)))
		}
	}
	return out
}

// HasCredentials reports whether key+cert exist in the secure store.
func (s Store) HasCredentials() bool {
	ks, err := s.openKS()
	if err != nil {
		return false
	}
	return ks.Has()
}

func (s Store) ingestSeqPath() string { return filepath.Join(s.Dir, ingestSeqFileName) }

// LoadIngestSeq returns the last persisted ingest sequence (0 if missing).
func (s Store) LoadIngestSeq() int64 {
	if data, err := os.ReadFile(s.ingestSeqPath()); err == nil {
		return parsePositiveInt(strings.TrimSpace(string(data)))
	}
	// Fall back to enrollment metadata for older installs (JSON only; no keychain).
	data, err := os.ReadFile(s.statePath())
	if err != nil {
		return 0
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return 0
	}
	if st.LastIngestSeq > 0 {
		return st.LastIngestSeq
	}
	return 0
}

func parsePositiveInt(s string) int64 {
	var seq int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		seq = seq*10 + int64(c-'0')
	}
	return seq
}

// SaveIngestSeq persists the last ACK'd StreamTelemetry sequence.
func (s Store) SaveIngestSeq(seq int64) error {
	if seq <= 0 {
		return nil
	}
	if err := s.ensureDir(); err != nil {
		return err
	}
	tmp := s.ingestSeqPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d\n", seq)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.ingestSeqPath())
}
