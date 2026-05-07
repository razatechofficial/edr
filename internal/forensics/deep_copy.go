package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func deepSHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0o750)
}

// copyFileBounded copies src to dstDir/baseName with per-file max size; returns entry.
func copyFileBounded(src, dstDir, baseName string, maxBytes int64) (CopiedFileEntry, error) {
	dst := filepath.Join(dstDir, baseName)
	fi, err := os.Stat(src)
	if err != nil {
		return CopiedFileEntry{Source: src, Dest: dst, Copied: false, Note: err.Error()}, err
	}
	if maxBytes > 0 && fi.Size() > maxBytes {
		return CopiedFileEntry{
			Source: src, Dest: dst, Size: fi.Size(), Copied: false,
			Note: fmt.Sprintf("file too large: %d > %d", fi.Size(), maxBytes),
		}, fmt.Errorf("oversized")
	}
	in, err := os.Open(src)
	if err != nil {
		return CopiedFileEntry{Source: src, Dest: dst, Copied: false, Note: err.Error()}, err
	}
	defer in.Close()
	if err := ensureDir(dstDir); err != nil {
		return CopiedFileEntry{Source: src, Copied: false, Note: err.Error()}, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return CopiedFileEntry{Source: src, Dest: dst, Copied: false, Note: err.Error()}, err
	}
	defer out.Close()
	h := sha256.New()
	n, err := io.Copy(out, io.TeeReader(in, h))
	if err != nil {
		_ = os.Remove(dst)
		return CopiedFileEntry{Source: src, Dest: dst, Copied: false, Note: err.Error()}, err
	}
	return CopiedFileEntry{
		Source: src, Dest: dst, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Copied: true,
	}, nil
}
