package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

type Writer struct {
	alertPath string
	auditPath string
	maxBytes  int64
}

func NewWriter(alertPath, auditPath string, maxBytes int64) *Writer {
	if maxBytes <= 0 {
		maxBytes = 5 * 1024 * 1024
	}
	return &Writer{alertPath: alertPath, auditPath: auditPath, maxBytes: maxBytes}
}

func (w *Writer) WriteAlert(v schema.Alert) error {
	return w.appendJSON(w.alertPath, v)
}

func (w *Writer) WriteAudit(v schema.AuditRecord) error {
	return w.appendJSON(w.auditPath, v)
}

func (w *Writer) appendJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := w.rotateIfNeeded(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
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
	sum, err := fileSHA256(rotated)
	if err != nil {
		return err
	}
	return os.WriteFile(rotated+".sha256", []byte(sum+"\n"), 0o640)
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
