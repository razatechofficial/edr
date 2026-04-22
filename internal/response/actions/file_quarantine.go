package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// QuarantineMeta is written next to the quarantined file.
type QuarantineMeta struct {
	OriginalPath  string    `json:"original_path"`
	SHA256        string    `json:"sha256"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	DetectionID   string    `json:"detection_id"`
}

// FileQuarantineAction moves a file into a hash-named directory under QuarantineDir.
type FileQuarantineAction struct {
	Path          string
	QuarantineDir string
	DetectionID   string
}

// Execute hashes, moves (or copy+delete), writes metadata (no symlink follow).
func (a *FileQuarantineAction) Execute(ctx context.Context) (rollback func(context.Context) error, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("file_quarantine panic: %v", r)
		}
	}()
	if a.Path == "" {
		return nil, fmt.Errorf("empty path")
	}
	clean, err := filepath.Abs(a.Path)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to quarantine symlink %q", clean)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", clean)
	}
	qroot, err := filepath.Abs(a.QuarantineDir)
	if err != nil {
		return nil, err
	}
	hash, err := sha256File(clean)
	if err != nil {
		return nil, err
	}
	destDir := filepath.Join(qroot, hash)
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return nil, err
	}
	origName := filepath.Base(clean)
	destPath := filepath.Join(destDir, origName)
	if err := os.Rename(clean, destPath); err != nil {
		if err := copyFile(clean, destPath); err != nil {
			return nil, err
		}
		_ = os.Remove(clean)
	}
	meta := QuarantineMeta{
		OriginalPath:  clean,
		SHA256:        hash,
		QuarantinedAt: time.Now().UTC(),
		DetectionID:   a.DetectionID,
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	metaPath := filepath.Join(destDir, hash+".meta.json")
	f, err := os.OpenFile(metaPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return nil, werr
	}
	if cerr := f.Close(); cerr != nil {
		return nil, cerr
	}
	orig := clean
	rollback = func(rctx context.Context) error {
		_ = rctx
		return os.Rename(destPath, orig)
	}
	return rollback, nil
}

func sha256File(path string) (string, error) {
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

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}
