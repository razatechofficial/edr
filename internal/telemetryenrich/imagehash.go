package telemetryenrich

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// FileSHA256Hex returns a lowercase hex SHA-256 of the file at path, reading at most maxBytes.
// Returns empty string if the file cannot be read or maxBytes <= 0.
func FileSHA256Hex(path string, maxBytes int64) string {
	if path == "" || maxBytes <= 0 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxBytes)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
