package ioc

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// HashType identifies the hash algorithm.
type HashType string

const (
	HashMD5    HashType = "md5"
	HashSHA1   HashType = "sha1"
	HashSHA256 HashType = "sha256"
)

// HashEntry represents a known-bad hash with metadata.
type HashEntry struct {
	Hash          string   `json:"hash"`
	Type          HashType `json:"type"`
	MalwareFamily string   `json:"malware_family,omitempty"`
	Source        string   `json:"source,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	FirstSeen     string   `json:"first_seen,omitempty"`
	Tags          []string `json:"tags,omitempty"`
}

// HashDB stores known-malicious file hashes for fast lookup.
// A Bloom filter provides sub-microsecond negative filtering before
// falling through to exact map lookups.
type HashDB struct {
	bloom  *BloomFilter
	sha256 map[string]*HashEntry
	sha1   map[string]*HashEntry
	md5    map[string]*HashEntry
	mu     sync.RWMutex
}

// NewHashDB creates a HashDB pre-sized for up to 1 million hashes at 0.1% false-positive rate.
func NewHashDB() *HashDB {
	return &HashDB{
		bloom:  NewBloomFilter(1_000_000, 0.001),
		sha256: make(map[string]*HashEntry),
		sha1:   make(map[string]*HashEntry),
		md5:    make(map[string]*HashEntry),
	}
}

// Add inserts a hash entry into the appropriate map and the Bloom filter.
func (db *HashDB) Add(entry HashEntry) {
	lower := strings.ToLower(entry.Hash)
	e := &HashEntry{
		Hash:          lower,
		Type:          entry.Type,
		MalwareFamily: entry.MalwareFamily,
		Source:        entry.Source,
		Severity:      entry.Severity,
		FirstSeen:     entry.FirstSeen,
		Tags:          entry.Tags,
	}

	db.mu.Lock()
	switch entry.Type {
	case HashSHA256:
		db.sha256[lower] = e
	case HashSHA1:
		db.sha1[lower] = e
	case HashMD5:
		db.md5[lower] = e
	}
	db.mu.Unlock()

	db.bloom.Add(lower)
}

// Lookup checks a hash against the Bloom filter, then falls back to exact maps.
// The hash is matched against all three maps (SHA256, SHA1, MD5).
func (db *HashDB) Lookup(hash string) (*HashEntry, bool) {
	lower := strings.ToLower(hash)

	if !db.bloom.Contains(lower) {
		return nil, false
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	if e, ok := db.sha256[lower]; ok {
		return e, true
	}
	if e, ok := db.sha1[lower]; ok {
		return e, true
	}
	if e, ok := db.md5[lower]; ok {
		return e, true
	}
	return nil, false
}

// LookupSHA256 performs a targeted lookup against SHA-256 hashes only.
func (db *HashDB) LookupSHA256(hash string) (*HashEntry, bool) {
	lower := strings.ToLower(hash)

	if !db.bloom.Contains(lower) {
		return nil, false
	}

	db.mu.RLock()
	defer db.mu.RUnlock()

	e, ok := db.sha256[lower]
	return e, ok
}

// LoadFromFile populates the database from a JSON or CSV file.
// File format is inferred from the extension.
//
// CSV format: hash,type,malware_family,source,severity,first_seen,tags
// Tags are semicolon-delimited within the field.
func (db *HashDB) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("hashdb: open %s: %w", path, err)
	}
	defer f.Close()

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return db.loadJSON(f)
	case ".csv":
		return db.loadCSV(f)
	default:
		return fmt.Errorf("hashdb: unsupported file format %q", filepath.Ext(path))
	}
}

func (db *HashDB) loadJSON(r io.Reader) error {
	var entries []HashEntry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return fmt.Errorf("hashdb: decode json: %w", err)
	}
	for _, e := range entries {
		db.Add(e)
	}
	return nil
}

func (db *HashDB) loadCSV(r io.Reader) error {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true

	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("hashdb: read csv header: %w", err)
	}
	if len(header) < 2 {
		return fmt.Errorf("hashdb: csv requires at least hash and type columns")
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("hashdb: read csv row: %w", err)
		}
		if len(record) < 2 {
			continue
		}

		entry := HashEntry{
			Hash: record[0],
			Type: HashType(record[1]),
		}
		if len(record) > 2 {
			entry.MalwareFamily = record[2]
		}
		if len(record) > 3 {
			entry.Source = record[3]
		}
		if len(record) > 4 {
			entry.Severity = record[4]
		}
		if len(record) > 5 {
			entry.FirstSeen = record[5]
		}
		if len(record) > 6 && record[6] != "" {
			entry.Tags = strings.Split(record[6], ";")
		}

		db.Add(entry)
	}
	return nil
}

// Count returns the total number of entries across all hash types.
func (db *HashDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.sha256) + len(db.sha1) + len(db.md5)
}

// Clear removes all entries and resets the Bloom filter.
func (db *HashDB) Clear() {
	db.mu.Lock()
	db.sha256 = make(map[string]*HashEntry)
	db.sha1 = make(map[string]*HashEntry)
	db.md5 = make(map[string]*HashEntry)
	db.mu.Unlock()

	db.bloom.Reset()
}
