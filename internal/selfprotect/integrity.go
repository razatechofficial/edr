package selfprotect

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
// On startup it computes SHA-256 hashes and creates encrypted backups.
// During operation it detects tampering and can self-restore from backup.
type IntegrityChecker struct {
	expectedHashes map[string]string // path → SHA-256 hex
	checkInterval  time.Duration
	logger         *zap.Logger
	backupDir      string
	encKey         []byte // 32-byte AES-256 key derived from machine context
	mu             sync.RWMutex
}

// NewIntegrityChecker computes baseline SHA-256 hashes for every path and
// stores encrypted backups in backupDir. It tracks agent binaries, config
// files, rule files, and model files.
func NewIntegrityChecker(paths []string, backupDir string, logger *zap.Logger) (*IntegrityChecker, error) {
	ic := &IntegrityChecker{
		expectedHashes: make(map[string]string, len(paths)),
		checkInterval:  60 * time.Second,
		logger:         logger,
		backupDir:      backupDir,
		encKey:         deriveBackupKey(paths),
	}

	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("integrity: create backup dir: %w", err)
	}

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

// DeriveBackupKey produces a 32-byte AES-256 key. If EDR_BACKUP_KEY is set
// (hex-encoded, 64 chars), it is decoded and used directly. Otherwise, the
// key is derived deterministically from hostname + paths. Production
// deployments SHOULD inject a proper key via the environment or config.
func deriveBackupKey(paths []string) []byte {
	if envKey := os.Getenv("EDR_BACKUP_KEY"); len(envKey) == 64 {
		if b, err := hex.DecodeString(envKey); err == nil && len(b) == 32 {
			return b
		}
	}
	h := sha256.New()
	hostname, _ := os.Hostname()
	h.Write([]byte(hostname))
	for _, p := range paths {
		h.Write([]byte(p))
	}
	h.Write([]byte("edr-integrity-backup-key"))
	return h.Sum(nil)
}

func sanitizePath(path string) string {
	s := strings.ReplaceAll(path, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.TrimLeft(s, "_")
	return s
}
