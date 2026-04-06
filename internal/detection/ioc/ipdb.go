package ioc

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// IPEntry represents a known-bad IP with reputation data.
type IPEntry struct {
	Address    string   `json:"address"`
	CIDR       string   `json:"cidr,omitempty"`
	Reputation string   `json:"reputation,omitempty"`
	Source     string   `json:"source,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Country    string   `json:"country,omitempty"`
	ASN        string   `json:"asn,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

// IPDB stores IP reputation data with support for exact match and CIDR range lookups.
type IPDB struct {
	exact map[string]*IPEntry
	cidrs []*cidrEntry
	mu    sync.RWMutex
}

type cidrEntry struct {
	network *net.IPNet
	entry   *IPEntry
}

// NewIPDB creates an empty IP reputation database.
func NewIPDB() *IPDB {
	return &IPDB{
		exact: make(map[string]*IPEntry),
	}
}

// Add inserts an IP entry. If CIDR is set the entry is stored as a range;
// otherwise it is stored as an exact-match entry.
func (db *IPDB) Add(entry IPEntry) {
	e := &IPEntry{
		Address:    entry.Address,
		CIDR:       entry.CIDR,
		Reputation: entry.Reputation,
		Source:     entry.Source,
		Severity:   entry.Severity,
		Country:    entry.Country,
		ASN:        entry.ASN,
		Tags:       entry.Tags,
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	if entry.CIDR != "" {
		_, ipNet, err := net.ParseCIDR(entry.CIDR)
		if err == nil {
			db.cidrs = append(db.cidrs, &cidrEntry{network: ipNet, entry: e})
			return
		}
	}

	db.exact[entry.Address] = e
}

// Lookup checks an IP against exact entries first, then iterates CIDR ranges.
// Supports both IPv4 and IPv6 addresses.
func (db *IPDB) Lookup(ip string) (*IPEntry, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if e, ok := db.exact[ip]; ok {
		return e, true
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, false
	}

	for _, c := range db.cidrs {
		if c.network.Contains(parsed) {
			return c.entry, true
		}
	}
	return nil, false
}

// LoadFromFile populates the database from a JSON or CSV file.
//
// CSV format: address,cidr,reputation,source,severity,country,asn,tags
// Tags are semicolon-delimited.
func (db *IPDB) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("ipdb: open %s: %w", path, err)
	}
	defer f.Close()

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return db.loadJSON(f)
	case ".csv":
		return db.loadCSV(f)
	default:
		return fmt.Errorf("ipdb: unsupported file format %q", filepath.Ext(path))
	}
}

func (db *IPDB) loadJSON(r io.Reader) error {
	var entries []IPEntry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return fmt.Errorf("ipdb: decode json: %w", err)
	}
	for _, e := range entries {
		db.Add(e)
	}
	return nil
}

func (db *IPDB) loadCSV(r io.Reader) error {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true

	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("ipdb: read csv header: %w", err)
	}
	if len(header) < 1 {
		return fmt.Errorf("ipdb: csv requires at least an address column")
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("ipdb: read csv row: %w", err)
		}
		if len(record) < 1 {
			continue
		}

		entry := IPEntry{Address: record[0]}
		if len(record) > 1 {
			entry.CIDR = record[1]
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
			entry.Country = record[5]
		}
		if len(record) > 6 {
			entry.ASN = record[6]
		}
		if len(record) > 7 && record[7] != "" {
			entry.Tags = strings.Split(record[7], ";")
		}

		db.Add(entry)
	}
	return nil
}

// Count returns the total number of entries (exact + CIDR).
func (db *IPDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.exact) + len(db.cidrs)
}
