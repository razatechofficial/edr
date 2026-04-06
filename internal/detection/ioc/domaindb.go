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

// DomainEntry represents a known-bad domain.
type DomainEntry struct {
	Domain     string   `json:"domain"`
	IsWildcard bool     `json:"is_wildcard,omitempty"`
	Reputation string   `json:"reputation,omitempty"`
	Source     string   `json:"source,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Category   string   `json:"category,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

// DomainDB stores domain reputation data with wildcard matching.
// Wildcards match any subdomain: *.evil.com matches sub.evil.com, a.b.evil.com, etc.
type DomainDB struct {
	exact     map[string]*DomainEntry
	wildcards map[string]*DomainEntry
	mu        sync.RWMutex
}

// NewDomainDB creates an empty domain reputation database.
func NewDomainDB() *DomainDB {
	return &DomainDB{
		exact:     make(map[string]*DomainEntry),
		wildcards: make(map[string]*DomainEntry),
	}
}

// Add inserts a domain entry. Wildcard entries (IsWildcard=true or Domain
// starting with "*.") are stored separately for hierarchical matching.
func (db *DomainDB) Add(entry DomainEntry) {
	domain := strings.ToLower(strings.TrimSpace(entry.Domain))
	e := &DomainEntry{
		Domain:     domain,
		IsWildcard: entry.IsWildcard,
		Reputation: entry.Reputation,
		Source:     entry.Source,
		Severity:   entry.Severity,
		Category:   entry.Category,
		Tags:       entry.Tags,
	}

	isWild := entry.IsWildcard || strings.HasPrefix(domain, "*.")

	db.mu.Lock()
	defer db.mu.Unlock()

	if isWild {
		base := strings.TrimPrefix(domain, "*.")
		e.IsWildcard = true
		e.Domain = "*." + base
		db.wildcards[base] = e
	} else {
		db.exact[domain] = e
	}
}

// Lookup checks a domain against exact entries, then walks up the domain
// hierarchy checking wildcards. For "sub.evil.com" it checks:
//
//	exact["sub.evil.com"] → wildcards["evil.com"] → wildcards["com"]
func (db *DomainDB) Lookup(domain string) (*DomainEntry, bool) {
	lower := strings.ToLower(strings.TrimSpace(domain))

	db.mu.RLock()
	defer db.mu.RUnlock()

	if e, ok := db.exact[lower]; ok {
		return e, true
	}

	parts := lower
	for {
		idx := strings.IndexByte(parts, '.')
		if idx < 0 {
			break
		}
		parent := parts[idx+1:]
		if e, ok := db.wildcards[parent]; ok {
			return e, true
		}
		parts = parent
	}

	return nil, false
}

// LoadFromFile populates the database from a JSON or CSV file.
//
// CSV format: domain,is_wildcard,reputation,source,severity,category,tags
// Tags are semicolon-delimited.
func (db *DomainDB) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("domaindb: open %s: %w", path, err)
	}
	defer f.Close()

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return db.loadJSON(f)
	case ".csv":
		return db.loadCSV(f)
	default:
		return fmt.Errorf("domaindb: unsupported file format %q", filepath.Ext(path))
	}
}

func (db *DomainDB) loadJSON(r io.Reader) error {
	var entries []DomainEntry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return fmt.Errorf("domaindb: decode json: %w", err)
	}
	for _, e := range entries {
		db.Add(e)
	}
	return nil
}

func (db *DomainDB) loadCSV(r io.Reader) error {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true

	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("domaindb: read csv header: %w", err)
	}
	if len(header) < 1 {
		return fmt.Errorf("domaindb: csv requires at least a domain column")
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("domaindb: read csv row: %w", err)
		}
		if len(record) < 1 {
			continue
		}

		entry := DomainEntry{Domain: record[0]}
		if len(record) > 1 {
			entry.IsWildcard = record[1] == "true" || record[1] == "1"
		}
		if len(record) > 2 {
			entry.Reputation = record[2]
		}
		if len(record) > 3 {
			entry.Source = record[3]
		}
		if len(record) > 4 {
			entry.Severity = record[4]
		}
		if len(record) > 5 {
			entry.Category = record[5]
		}
		if len(record) > 6 && record[6] != "" {
			entry.Tags = strings.Split(record[6], ";")
		}

		db.Add(entry)
	}
	return nil
}

// Count returns the total number of entries (exact + wildcard).
func (db *DomainDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.exact) + len(db.wildcards)
}
