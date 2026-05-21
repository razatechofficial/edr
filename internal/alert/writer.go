package alert

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

type Writer struct {
	alertPath      string
	auditPath      string
	maxBytes       int64
	encKey         []byte // 32-byte AES-256 key; nil = plaintext
	productVersion string
}

func NewWriter(alertPath, auditPath string, maxBytes int64) *Writer {
	if maxBytes <= 0 {
		maxBytes = 5 * 1024 * 1024
	}
	return &Writer{alertPath: alertPath, auditPath: auditPath, maxBytes: maxBytes}
}

// SetProductVersion sets the agent version label embedded in exported OCSF alerts.
func (w *Writer) SetProductVersion(version string) {
	w.productVersion = version
}

// NewEncryptedWriter creates a writer that encrypts each rotated alert file
// with AES-256-GCM and appends an HMAC-SHA256 integrity tag.
func NewEncryptedWriter(alertPath, auditPath string, maxBytes int64, encKey []byte) *Writer {
	w := NewWriter(alertPath, auditPath, maxBytes)
	if len(encKey) == 32 {
		w.encKey = encKey
	}
	return w
}

func (w *Writer) WriteAlert(v schema.Alert) error {
	body, err := MarshalOCSF(v, w.productVersion)
	if err != nil {
		return err
	}
	return w.appendBytes(w.alertPath, body)
}

func (w *Writer) WriteAudit(v schema.AuditRecord) error {
	return w.appendJSON(w.auditPath, v)
}

func (w *Writer) appendJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return w.appendBytes(path, b)
}

func (w *Writer) appendBytes(path string, b []byte) error {
	if path == "" {
		return fmt.Errorf("alert writer: output path is empty (set logging.alert_file / logging.audit_file or data_dir)")
	}
	// 0755 so operators and log forwarders can traverse and read alerts (typical /var/log semantics).
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := w.rotateIfNeeded(path); err != nil {
		return err
	}
	// 0644 so edrctl and SIEM local readers need not run as root.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

func (w *Writer) rotateIfNeeded(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Size() < w.maxBytes {
		return nil
	}
	rotated := fmt.Sprintf("%s.%s", path, time.Now().UTC().Format("20060102-150405"))
	if err := os.Rename(path, rotated); err != nil {
		return err
	}

	if w.encKey != nil {
		if err := w.encryptRotatedFile(rotated); err != nil {
			return fmt.Errorf("encrypt rotated file %s: %w", rotated, err)
		}
	}

	sum, err := fileSHA256(rotated)
	if err != nil {
		return err
	}

	sigData := sum
	if w.encKey != nil {
		mac := hmac.New(sha256.New, w.encKey)
		mac.Write([]byte(sum))
		sigData = sum + " hmac:" + hex.EncodeToString(mac.Sum(nil))
	}

	return os.WriteFile(rotated+".sha256", []byte(sigData+"\n"), 0o640)
}

func (w *Writer) encryptRotatedFile(path string) error {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(w.encKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	encPath := path + ".enc"
	if err := os.WriteFile(encPath, ciphertext, 0o600); err != nil {
		return err
	}

	return os.Rename(encPath, path)
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
