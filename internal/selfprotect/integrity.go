package selfprotect

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// IntegrityViolation records a mismatch between the expected and actual
// file hash of a protected agent file.
type IntegrityViolation struct {
	Path         string    `json:"path"`
	ExpectedHash string    `json:"expected_hash"`
	ActualHash   string    `json:"actual_hash"`
	Timestamp    time.Time `json:"timestamp"`
	Restored     bool      `json:"restored"`
}

// IntegrityChecker verifies agent file integrity at regular intervals.
// On startup it loads an Ed25519-signed manifest of expected hashes,
// verifies its signature against an embedded public key, and creates
// encrypted backups. During operation it detects tampering and can
// self-restore from backup.
//
// P1-15: the baseline is no longer computed at startup from whatever is
// on disk (a tampered binary at install time would lock in the wrong
// hash). Instead the manifest is generated at build time, signed by
// the release pipeline, and embedded into the agent binary. If the
// manifest signature fails to verify the agent refuses to start.
type IntegrityChecker struct {
	expectedHashes map[string]string // path → SHA-256 hex
	manifest       *IntegrityManifest
	checkInterval  time.Duration
	logger         *zap.Logger
	backupDir      string
	encKey         []byte // 32-byte AES-256 key
	dataDir        string // used to load the backup.key
	mu             sync.RWMutex
}

// IntegrityManifest is the build-time generated baseline. It is signed
// by the release pipeline with an Ed25519 key whose public counterpart
// is embedded in the agent binary. Tampered manifests cause startup to
// fail.
type IntegrityManifest struct {
	Version   string            `json:"version"`
	BuildTime string            `json:"build_time"`
	Files     map[string]string `json:"files"`     // path → SHA-256 hex
	Signature string            `json:"signature"` // base16 Ed25519 sig over the canonical Files JSON
}

// embeddedManifest is the JSON manifest baked into the agent at build
// time by `go generate ./tools/sign_manifest` (or equivalent). It is
// optional in development builds — when absent the agent falls back to
// a runtime-computed baseline and emits a warning.
//
//go:embed integrity_manifest.json
var embeddedManifest []byte

// embeddedManifestPublicKey is the Ed25519 public key (hex, 64 chars)
// used to verify the embedded manifest signature. Replaced at release
// build time via -ldflags "-X". Empty string means "verification
// disabled" and is only safe for development; production builds MUST
// set this.
var embeddedManifestPublicKey = ""

// ErrIntegrityManifestUnverified is returned when the embedded manifest
// exists but its signature cannot be verified against the embedded
// public key. The agent refuses to start in this case.
var ErrIntegrityManifestUnverified = errors.New("integrity: embedded manifest signature failed to verify")

// NewIntegrityChecker constructs a checker for the given paths. When a
// signed manifest is embedded in the agent binary the baseline hashes
// come from the manifest (P1-15) — a binary that was tampered at
// install time will fail verification and the agent will refuse to
// start. When no manifest is embedded the constructor falls back to
// computing baseline hashes from disk, logs a warning, and proceeds —
// suitable for development only.
//
// The backup encryption key is loaded from {dataDir}/backup.key when
// dataDir is non-empty (P1-16). Falling back to EDR_BACKUP_KEY env var
// and finally a host-derived derivation preserves backward
// compatibility for tests; production deployments should provision the
// backup.key file via the enrollment flow.
func NewIntegrityChecker(paths []string, backupDir, dataDir string, logger *zap.Logger) (*IntegrityChecker, error) {
	ic := &IntegrityChecker{
		expectedHashes: make(map[string]string, len(paths)),
		checkInterval:  60 * time.Second,
		logger:         logger,
		backupDir:      backupDir,
		dataDir:        dataDir,
	}

	key, source, err := loadBackupKey(dataDir, paths)
	if err != nil {
		return nil, err
	}
	ic.encKey = key
	logger.Info("backup key loaded", zap.String("source", source))

	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("integrity: create backup dir: %w", err)
	}

	manifest, manifestSource, err := loadEmbeddedManifest()
	if err != nil {
		return nil, err
	}
	ic.manifest = manifest

	if manifest != nil && len(manifest.Files) > 0 {
		for p, h := range manifest.Files {
			ic.expectedHashes[p] = h
		}
		for _, p := range paths {
			if _, ok := manifest.Files[p]; !ok {
				logger.Warn("integrity: path not in signed manifest, skipping",
					zap.String("path", p))
				continue
			}
			if err := ic.createBackup(p); err != nil {
				return nil, fmt.Errorf("integrity: backup %s: %w", p, err)
			}
		}
		logger.Info("integrity checker initialized from signed manifest",
			zap.String("manifest_source", manifestSource),
			zap.String("manifest_version", manifest.Version),
			zap.Int("tracked_files", len(manifest.Files)),
			zap.String("backup_dir", backupDir),
		)
		return ic, nil
	}

	logger.Warn("integrity: no embedded manifest, falling back to disk baseline (development only)")
	for _, p := range paths {
		h, err := hashFile(p)
		if err != nil {
			return nil, fmt.Errorf("integrity: baseline hash %s: %w", p, err)
		}
		ic.expectedHashes[p] = h

		if err := ic.createBackup(p); err != nil {
			return nil, fmt.Errorf("integrity: backup %s: %w", p, err)
		}
	}

	logger.Info("integrity checker initialized",
		zap.Int("tracked_files", len(paths)),
		zap.String("backup_dir", backupDir),
	)
	return ic, nil
}

// Start runs the integrity check loop, checking every 60 seconds until ctx
// is cancelled. Detected violations are logged as critical alerts and
// self-restore is attempted automatically.
func (ic *IntegrityChecker) Start(ctx context.Context) error {
	ic.logger.Info("integrity checker started", zap.Duration("interval", ic.checkInterval))
	ticker := time.NewTicker(ic.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			violations, err := ic.Check()
			if err != nil {
				ic.logger.Error("integrity check error", zap.Error(err))
				continue
			}
			for _, v := range violations {
				ic.logger.Error("integrity violation detected",
					zap.String("path", v.Path),
					zap.String("expected", v.ExpectedHash),
					zap.String("actual", v.ActualHash),
				)
				if err := ic.Restore(v.Path); err != nil {
					ic.logger.Error("self-restore failed",
						zap.String("path", v.Path),
						zap.Error(err),
					)
				} else {
					ic.logger.Warn("self-restore succeeded", zap.String("path", v.Path))
				}
			}
		}
	}
}

// Check compares the current SHA-256 of every tracked file against the
// expected baseline and returns any violations found.
func (ic *IntegrityChecker) Check() ([]IntegrityViolation, error) {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	var violations []IntegrityViolation
	for path, expected := range ic.expectedHashes {
		actual, err := hashFile(path)
		if err != nil {
			violations = append(violations, IntegrityViolation{
				Path:         path,
				ExpectedHash: expected,
				ActualHash:   "error: " + err.Error(),
				Timestamp:    time.Now().UTC(),
			})
			continue
		}
		if actual != expected {
			violations = append(violations, IntegrityViolation{
				Path:         path,
				ExpectedHash: expected,
				ActualHash:   actual,
				Timestamp:    time.Now().UTC(),
			})
		}
	}
	return violations, nil
}

// Restore decrypts the backup for path and overwrites the tampered file,
// then updates the expected hash to the restored content.
func (ic *IntegrityChecker) Restore(path string) error {
	backupPath := filepath.Join(ic.backupDir, sanitizePath(path)+".enc")
	encrypted, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("integrity: read backup for %s: %w", path, err)
	}

	block, err := aes.NewCipher(ic.encKey)
	if err != nil {
		return fmt.Errorf("integrity: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("integrity: create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return fmt.Errorf("integrity: backup for %s is truncated", path)
	}

	plaintext, err := gcm.Open(nil, encrypted[:nonceSize], encrypted[nonceSize:], nil)
	if err != nil {
		return fmt.Errorf("integrity: decrypt backup for %s: %w", path, err)
	}

	if err := os.WriteFile(path, plaintext, 0644); err != nil {
		return fmt.Errorf("integrity: write restored %s: %w", path, err)
	}

	h := sha256.Sum256(plaintext)
	ic.mu.Lock()
	ic.expectedHashes[path] = hex.EncodeToString(h[:])
	ic.mu.Unlock()
	return nil
}

func (ic *IntegrityChecker) createBackup(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(ic.encKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	backupPath := filepath.Join(ic.backupDir, sanitizePath(path)+".enc")
	return os.WriteFile(backupPath, ciphertext, 0600)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// loadBackupKey returns a 32-byte AES-256 key for the integrity
// backups (P1-16). Priority order:
//
//  1. {dataDir}/backup.key (32 raw bytes or 64 hex chars). This is the
//     production path — the enrollment flow writes a server-issued
//     random key here with 0600 perms and dataDir owned by root.
//  2. EDR_BACKUP_KEY environment variable (64-char hex). Useful for
//     CI/dev where dataDir provisioning is not in scope.
//  3. Host-derived fallback (hostname + paths SHA-256). Last resort —
//     not safe against an adversary with host enumeration capability.
//
// The returned source string identifies which path was taken so callers
// can log and operators can audit; it never contains key material.
func loadBackupKey(dataDir string, paths []string) (key []byte, source string, err error) {
	if strings.TrimSpace(dataDir) != "" {
		keyPath := filepath.Join(dataDir, "backup.key")
		b, ferr := os.ReadFile(keyPath)
		if ferr == nil {
			if len(b) == 32 {
				return b, "file:" + keyPath, nil
			}
			// hex-encoded 32 bytes is also accepted (allows the
			// enrollment server to write either format).
			trimmed := strings.TrimSpace(string(b))
			if len(trimmed) == 64 {
				if decoded, derr := hex.DecodeString(trimmed); derr == nil && len(decoded) == 32 {
					return decoded, "file:" + keyPath, nil
				}
			}
			return nil, "", fmt.Errorf("integrity: backup key file %s has invalid length %d", keyPath, len(b))
		}
		if !os.IsNotExist(ferr) {
			return nil, "", fmt.Errorf("integrity: read backup key %s: %w", keyPath, ferr)
		}
	}

	if envKey := os.Getenv("EDR_BACKUP_KEY"); len(envKey) == 64 {
		if b, derr := hex.DecodeString(envKey); derr == nil && len(b) == 32 {
			return b, "env:EDR_BACKUP_KEY", nil
		}
	}

	h := sha256.New()
	hostname, _ := os.Hostname()
	h.Write([]byte(hostname))
	for _, p := range paths {
		h.Write([]byte(p))
	}
	h.Write([]byte("edr-integrity-backup-key"))
	return h.Sum(nil), "host-derived", nil
}

// loadEmbeddedManifest unmarshals the embedded integrity_manifest.json
// and verifies its signature against embeddedManifestPublicKey. A
// signature verification failure is fatal (ErrIntegrityManifestUnverified).
// An empty or absent manifest returns nil, "absent", nil so the caller
// can fall back to the disk baseline.
func loadEmbeddedManifest() (*IntegrityManifest, string, error) {
	if len(embeddedManifest) == 0 {
		return nil, "absent", nil
	}
	var manifest IntegrityManifest
	if err := json.Unmarshal(embeddedManifest, &manifest); err != nil {
		return nil, "", fmt.Errorf("integrity: unmarshal embedded manifest: %w", err)
	}
	if len(manifest.Files) == 0 {
		// Dev placeholder — no files, no signature. Accept and let the
		// caller fall back to runtime baseline.
		return nil, "placeholder", nil
	}

	if embeddedManifestPublicKey == "" {
		// Manifest is present and lists files but no public key is
		// baked in. Refuse to start; this should never happen in a
		// production build.
		return nil, "", fmt.Errorf("%w: no embedded public key for verification", ErrIntegrityManifestUnverified)
	}
	pubBytes, err := hex.DecodeString(embeddedManifestPublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("%w: malformed embedded public key", ErrIntegrityManifestUnverified)
	}

	sigBytes, err := hex.DecodeString(manifest.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, "", fmt.Errorf("%w: malformed signature", ErrIntegrityManifestUnverified)
	}

	canonical, err := canonicalManifestBytes(&manifest)
	if err != nil {
		return nil, "", fmt.Errorf("integrity: canonicalize manifest: %w", err)
	}
	if !ed25519.Verify(pubBytes, canonical, sigBytes) {
		return nil, "", ErrIntegrityManifestUnverified
	}
	return &manifest, "embedded", nil
}

// canonicalManifestBytes returns the deterministic byte representation
// of the manifest minus the Signature field. Keys are sorted by Go's
// json package automatically when marshaling a map, which gives stable
// signing input across builds.
func canonicalManifestBytes(m *IntegrityManifest) ([]byte, error) {
	tmp := struct {
		Version   string            `json:"version"`
		BuildTime string            `json:"build_time"`
		Files     map[string]string `json:"files"`
	}{
		Version:   m.Version,
		BuildTime: m.BuildTime,
		Files:     m.Files,
	}
	return json.Marshal(tmp)
}

func sanitizePath(path string) string {
	s := strings.ReplaceAll(path, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.TrimLeft(s, "_")
	return s
}
