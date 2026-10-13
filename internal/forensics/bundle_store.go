package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// StoredBundle is an artifact bundle as it is written to disk.
//
// The alert metadata travels with the evidence rather than only in the
// filename: a bundle that cannot say which detection produced it, on which
// endpoint, is a collection of facts with nothing to attach them to.
//
// The field order is load-bearing. Go encodes a struct in declaration order, and
// the shipper reads only the first megabyte of a file to find out which
// detection a bundle belongs to — a bundle can be far larger than that, and
// decoding all of it just to read an identifier would be a denial of service
// against the agent. Moving Bundle ahead of Alert would push the attribution
// past that bound, and every large bundle would ship with no alert against it.
type StoredBundle struct {
	Alert     AlertTriggerMeta `json:"alert"`
	Collected time.Time        `json:"collected_at"`
	Bundle    *ArtifactBundle  `json:"bundle"`
}

// WriteResult describes what was written.
type WriteResult struct {
	Path string
	// SHA256 is the digest of the file as written. It is the starting point of
	// any chain of custody: without a digest recorded at collection time, there
	// is nothing later to compare against.
	SHA256 string
	Bytes  int64
}

// safeNameChars keeps a filename to characters that are harmless on every
// platform. Alert and rule identifiers come from detection content, and content
// is not necessarily well-behaved.
var safeNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeName(s, fallback string) string {
	s = safeNameChars.ReplaceAllString(strings.TrimSpace(s), "_")
	s = strings.Trim(s, "._-")
	if s == "" {
		return fallback
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// WriteBundle serialises a bundle beneath dir and returns where it landed.
//
// Collecting evidence and then discarding it is worse than not collecting it:
// the cost is paid — the host is scanned, processes and memory are read — and
// the only thing produced is the belief that evidence exists.
func WriteBundle(dir string, meta AlertTriggerMeta, bundle *ArtifactBundle) (WriteResult, error) {
	var res WriteResult
	if bundle == nil {
		return res, fmt.Errorf("forensics: nothing to write")
	}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return res, fmt.Errorf("forensics: no artifact directory configured")
	}
	// 0700: the bundle holds process arguments, environment variables and file
	// paths from the host at the moment of a detection.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return res, fmt.Errorf("forensics: create artifact dir: %w", err)
	}

	collected := time.Now().UTC()
	stored := StoredBundle{Alert: meta, Collected: collected, Bundle: bundle}
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return res, fmt.Errorf("forensics: encode bundle: %w", err)
	}

	name := fmt.Sprintf("%s_%s.json",
		collected.Format("20060102T150405Z"),
		safeName(meta.AlertID, "unattributed"),
	)
	path := filepath.Join(dir, name)

	// Temp plus rename, so a bundle that is being read is never half-written.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return res, fmt.Errorf("forensics: write bundle: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return res, fmt.Errorf("forensics: commit bundle: %w", err)
	}

	sum := sha256.Sum256(data)
	return WriteResult{
		Path:   path,
		SHA256: hex.EncodeToString(sum[:]),
		Bytes:  int64(len(data)),
	}, nil
}
