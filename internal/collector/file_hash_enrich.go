package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

const fileHashMaxBytes = 50 << 20

// EnrichFileSHA256IfEligible hashes small files on create/write-style operations.
func EnrichFileSHA256IfEligible(path, operation string) string {
	op := strings.ToLower(strings.TrimSpace(operation))
	if op != "write" && op != "create" && op != "open" {
		return ""
	}
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() == 0 || fi.Size() > fileHashMaxBytes {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
