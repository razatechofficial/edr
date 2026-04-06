package response

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// QuarantineManifest records chain-of-custody metadata for a quarantined file.
type QuarantineManifest struct {
	OriginalPath   string    `json:"original_path"`
	QuarantinePath string    `json:"quarantine_path"`
	ManifestPath   string    `json:"manifest_path"`
	SHA256         string    `json:"sha256"`
	FileSize       int64     `json:"file_size"`
	FileMode       string    `json:"file_mode"`
	QuarantinedAt  time.Time `json:"quarantined_at"`
	QuarantinedBy  string    `json:"quarantined_by"`
	Reason         string    `json:"reason"`
	AlertID        string    `json:"alert_id,omitempty"`
	Encrypted      bool      `json:"encrypted"`
	NonceHex       string    `json:"nonce_hex,omitempty"`
}

// FileHandler implements ActionHandler for file quarantine with AES-256-GCM
// encryption and chain-of-custody tracking.
type FileHandler struct {
	logger        *zap.Logger
	quarantineDir string
	encKey        []byte // 32-byte AES-256 master key
}

// NewFileHandler creates a handler that quarantines files into dir, encrypted
// with the supplied 32-byte key. If key is nil, files are quarantined without
// encryption.
func NewFileHandler(logger *zap.Logger, quarantineDir string, encryptionKey []byte) (*FileHandler, error) {
	if quarantineDir == "" {
		quarantineDir = "/var/lib/edr/quarantine"
	}
	if err := os.MkdirAll(quarantineDir, 0o750); err != nil {
		return nil, fmt.Errorf("file handler: create quarantine dir: %w", err)
	}
	if len(encryptionKey) != 0 && len(encryptionKey) != 32 {
		return nil, fmt.Errorf("file handler: encryption key must be 32 bytes (AES-256), got %d", len(encryptionKey))
	}
	return &FileHandler{
		logger:        logger,
		quarantineDir: quarantineDir,
		encKey:        encryptionKey,
	}, nil
}

// Execute quarantines the file at params["path"]. Optional params: "reason",
// "alert_id", "operator".
func (h *FileHandler) Execute(ctx context.Context, params map[string]interface{}) (*StepResult, error) {
	srcPath := stringParam(params, "path")
	if srcPath == "" {
		return failResult(ActionQuarantineFile, "path parameter required"),
			fmt.Errorf("file handler: missing path param")
	}

	info, err := os.Stat(srcPath)
	if err != nil {
		return failResult(ActionQuarantineFile, fmt.Sprintf("stat %s: %s", srcPath, err)),
			fmt.Errorf("file handler: stat %s: %w", srcPath, err)
	}
	if info.IsDir() {
		return failResult(ActionQuarantineFile, "cannot quarantine a directory"),
			fmt.Errorf("file handler: %s is a directory", srcPath)
	}

	hash, err := sha256File(srcPath)
	if err != nil {
		return failResult(ActionQuarantineFile, err.Error()), err
	}

	baseName := fmt.Sprintf("%s_%s", time.Now().UTC().Format("20060102T150405Z"), filepath.Base(srcPath))
	dstPath := filepath.Join(h.quarantineDir, baseName+".quarantined")

	var nonceHex string
	if len(h.encKey) == 32 {
		nonce, encErr := h.encryptAndMove(srcPath, dstPath)
		if encErr != nil {
			return failResult(ActionQuarantineFile, encErr.Error()), encErr
		}
		nonceHex = hex.EncodeToString(nonce)
	} else {
		if mvErr := moveFile(srcPath, dstPath); mvErr != nil {
			return failResult(ActionQuarantineFile, mvErr.Error()), mvErr
		}
	}

	manifest := QuarantineManifest{
		OriginalPath:   srcPath,
		QuarantinePath: dstPath,
		SHA256:         hash,
		FileSize:       info.Size(),
		FileMode:       info.Mode().String(),
		QuarantinedAt:  time.Now().UTC(),
		QuarantinedBy:  stringParam(params, "operator"),
		Reason:         stringParam(params, "reason"),
		AlertID:        stringParam(params, "alert_id"),
		Encrypted:      len(h.encKey) == 32,
		NonceHex:       nonceHex,
	}
	manifest.ManifestPath = dstPath + ".manifest.json"
	if err := writeManifest(manifest); err != nil {
		h.logger.Error("failed to write quarantine manifest", zap.Error(err))
	}

	return okResult(ActionQuarantineFile,
		fmt.Sprintf("quarantined %s → %s (sha256:%s)", srcPath, dstPath, hash[:16])), nil
}

// Rollback restores the quarantined file to its original location if the
// manifest exists.
func (h *FileHandler) Rollback(ctx context.Context, params map[string]interface{}) error {
	srcPath := stringParam(params, "path")
	if srcPath == "" {
		return fmt.Errorf("file handler rollback: missing path param")
	}

	// Find the most recent manifest for this original path.
	matches, _ := filepath.Glob(filepath.Join(h.quarantineDir, "*.manifest.json"))
	for i := len(matches) - 1; i >= 0; i-- {
		data, err := os.ReadFile(matches[i])
		if err != nil {
			continue
		}
		var m QuarantineManifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if m.OriginalPath != srcPath {
			continue
		}
		if m.Encrypted {
			return fmt.Errorf("file handler rollback: encrypted quarantine requires manual restore")
		}
		if err := moveFile(m.QuarantinePath, m.OriginalPath); err != nil {
			return fmt.Errorf("file handler rollback: %w", err)
		}
		_ = os.Remove(matches[i])
		return nil
	}
	return fmt.Errorf("file handler rollback: no quarantine manifest found for %s", srcPath)
}

// encryptAndMove reads src, encrypts with AES-256-GCM, writes to dst, then
// removes src. Returns the nonce used.
func (h *FileHandler) encryptAndMove(src, dst string) ([]byte, error) {
	plaintext, err := os.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("file handler: read source: %w", err)
	}

	block, err := aes.NewCipher(h.encKey)
	if err != nil {
		return nil, fmt.Errorf("file handler: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("file handler: create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("file handler: generate nonce: %w", err)
	}

	// Ciphertext = nonce || encrypted(plaintext).
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	if err := os.WriteFile(dst, ciphertext, 0o600); err != nil {
		return nil, fmt.Errorf("file handler: write encrypted file: %w", err)
	}
	if err := os.Remove(src); err != nil {
		return nil, fmt.Errorf("file handler: remove original after quarantine: %w", err)
	}
	return nonce, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("file handler: sha256 open: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("file handler: sha256 read: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeManifest(m QuarantineManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("file handler: marshal manifest: %w", err)
	}
	return os.WriteFile(m.ManifestPath, data, 0o640)
}

// moveFile copies src to dst then removes src. It falls back to copy+remove
// when os.Rename fails (cross-device).
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("file handler: open source for copy: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("file handler: create destination: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("file handler: copy data: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("file handler: close destination: %w", err)
	}
	return os.Remove(src)
}
