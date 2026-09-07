package xdrclient

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

func (s Store) metadataPaths() []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	add(s.statePath())
	if dd := strings.TrimSpace(s.DataDir); dd != "" {
		add(filepath.Join(dd, stateFileName))
	}
	return out
}

// Load reads enrollment metadata and certificate PEM. If enrollment.json was
// wiped (Windows ACL / MSI folder recreate) but the device cert is still in
// DPAPI or the file store, rebuild metadata so Connect stream can enable ingest.
func (s Store) Load() (State, error) {
	var firstErr error
	for _, p := range s.metadataPaths() {
		data, err := os.ReadFile(p)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		var st State
		if err := json.Unmarshal(data, &st); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		certPEM, err := s.LoadCertificatePEM()
		if err != nil {
			return State{}, err
		}
		st.CertificatePEM = string(certPEM)
		if st.SecureStorage == "" {
			st.SecureStorage = s.BackendName()
		}
		if len(st.IngestHosts) == 0 {
			st.IngestHosts = DefaultIngestHosts()
		}
		return st, nil
	}
	if !s.HasAnyCredentials() {
		if firstErr == nil {
			firstErr = fmt.Errorf("enrollment.json: file not found")
		}
		return State{}, firstErr
	}
	st, err := s.recoverMetadataFromCert()
	if err != nil {
		if firstErr != nil {
			return State{}, fmt.Errorf("%v", firstErr)
		}
		return State{}, err
	}
	_ = s.SaveMetadata(st)
	return st, nil
}

func (s Store) recoverMetadataFromCert() (State, error) {
	certPEM, err := s.LoadCertificatePEM()
	if err != nil || len(certPEM) == 0 {
		return State{}, fmt.Errorf("load certificate: %w", err)
	}
	agentID, err := AgentIDFromCert(string(certPEM))
	if err != nil || strings.TrimSpace(agentID) == "" {
		return State{}, fmt.Errorf("cannot derive agent_id from device certificate")
	}
	notAfter, _ := CertNotAfter(string(certPEM))
	return State{
		AgentID:        agentID,
		MachineID:      MachineIDFromCert(string(certPEM)),
		CertificatePEM: string(certPEM),
		CAChainPEM:     s.LoadCAChainPEM(),
		IngestHosts:    DefaultIngestHosts(),
		HeartbeatSec:   30,
		CertNotAfter:   notAfter,
		EnrolledAt:     time.Now().UTC(),
		SecureStorage:  s.BackendName(),
	}, nil
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
	if err := replaceFile(s.statePath(), meta, 0o644); err != nil {
		return err
	}
	s.relaxIdentityPerms()
	if dd := strings.TrimSpace(s.DataDir); dd != "" && filepath.Clean(dd) != filepath.Clean(s.Dir) {
		_ = replaceFile(filepath.Join(dd, stateFileName), meta, 0o644)
	}
	PublishEnrollmentSidecar(s.DataDir, s.Dir)
	return nil
}

func replaceFile(path string, data []byte, perm os.FileMode) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	clearFileWriteBarrier(path)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(path)
		if err2 := os.Rename(tmp, path); err2 != nil {
			_ = os.Remove(tmp)
			if err3 := os.WriteFile(path, data, perm); err3 != nil {
				return err
			}
		}
	}
	_ = os.Chmod(path, perm)
	grantUsersRead(path)
	return nil
}

// PublishEnrollmentSidecar lets the unelevated console read enrollment.json
// after restrictSensitiveTree locks xdr-tls to SYSTEM+Administrators.
func PublishEnrollmentSidecar(dataDir, certDir string) {
	grantUsersRead(filepath.Join(strings.TrimSpace(certDir), stateFileName))
	if dd := strings.TrimSpace(dataDir); dd != "" {
		grantUsersRead(filepath.Join(dd, stateFileName))
		grantUsersRead(filepath.Join(dd, "xdr-tls", stateFileName))
	}
}

// RebindDaemonReadable rewrites key+cert+metadata so the machine-wide sensor
// can load identity (System keychain + sealed files, world-readable sidecar).
func (s Store) RebindDaemonReadable(st State) error {
	key, err := s.LoadPrivateKeyPEM()
	if err != nil {
		return err
	}
	csr, _ := s.LoadCSRPEM()
	return s.ExportDaemonReadable(st, key, string(csr))
}

// ExportDaemonReadable writes a file-backend copy of key+cert so LaunchDaemon /
// SYSTEM can load identity when YAML pins secure_storage=file (the console
// user's login Keychain is not visible to the service).
func (s Store) ExportDaemonReadable(st State, keyPEM []byte, csrPEM string) error {
	if len(keyPEM) == 0 {
		return fmt.Errorf("export identity: empty key")
	}
	backend := strings.ToLower(strings.TrimSpace(s.Backend))
	name := s.BackendName()
	if backend == keystore.BackendFile || name == keystore.BackendFile {
		s.relaxIdentityPerms()
		PublishEnrollmentSidecar(s.DataDir, s.Dir)
		return os.Chmod(s.statePath(), 0o644)
	}
	// Windows sensor reads machine-scope DPAPI. A second file-backend Save
	// used to rewrite enrollment.json via Rename-over-existing, which fails
	// on Windows and left Connect stream looking at a missing sidecar.
	if runtime.GOOS == "windows" && name == keystore.BackendDPAPI {
		s.relaxIdentityPerms()
		return s.persistMetadata(st)
	}
	file := Store{Dir: s.Dir, DataDir: s.DataDir, Backend: keystore.BackendFile}
	return file.SaveWithCSR(st, keyPEM, csrPEM)
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
	return s.hasOnBackend(s.Backend)
}

func (s Store) hasOnBackend(backend string) bool {
	if s.hasIdentityBlobs(backend) {
		return true
	}
	ks, err := keystore.New(keystore.Options{Backend: backend, Dir: s.Dir, DataDir: s.DataDir})
	return err == nil && ks.Has()
}

// hasIdentityBlobs is true when key+cert files exist. Used when DPAPI New()
// cannot probe (UAC split token / ACL) but LocalSystem can still load them.
func (s Store) hasIdentityBlobs(backend string) bool {
	dir := strings.TrimSpace(s.Dir)
	if dir == "" {
		return false
	}
	dpapi := fileExists(dir, "agent.key.dpapi") && fileExists(dir, "agent.crt.dpapi")
	sealed := fileExists(dir, "agent.key.enc") && fileExists(dir, "agent.crt.enc")
	plain := fileExists(dir, "agent.key") && fileExists(dir, "agent.crt")
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", "auto":
		return dpapi || sealed || plain
	case "dpapi":
		return dpapi
	case "file":
		return sealed || plain
	default:
		return false
	}
}

// HasAnyCredentials is true when any supported backend has a device cert.
func (s Store) HasAnyCredentials() bool {
	if s.HasCredentials() {
		return true
	}
	_, ok := s.existingBackend()
	return ok
}

// WithExistingCredentials points the store at the backend that actually holds
// the device cert (DPAPI vs file). Config can say "file" after a Windows enroll.
func (s Store) WithExistingCredentials() Store {
	if b, ok := s.existingBackend(); ok {
		s.Backend = b
	}
	return s
}

func (s Store) existingBackend() (string, bool) {
	order := []string{s.Backend, "dpapi", "file", "keychain"}
	seen := map[string]struct{}{}
	for _, b := range order {
		b = strings.ToLower(strings.TrimSpace(b))
		if b == "" || b == "auto" {
			continue
		}
		if _, ok := seen[b]; ok {
			continue
		}
		seen[b] = struct{}{}
		if s.hasOnBackend(b) {
			return b, true
		}
	}
	return s.Backend, false
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
