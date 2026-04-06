package ioc

import (
	"fmt"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/schema"
)

// MatchResult contains the details of an IOC match.
type MatchResult struct {
	Matched       bool
	Type          string // hash|ip|domain
	Indicator     string
	Severity      string
	Source        string
	Tags          []string
	MalwareFamily string
}

// MatcherStats exposes runtime counters for monitoring.
type MatcherStats struct {
	HashLookups   uint64
	HashMatches   uint64
	IPLookups     uint64
	IPMatches     uint64
	DomainLookups uint64
	DomainMatches uint64
}

// Matcher orchestrates IOC lookups across all databases.
type Matcher struct {
	hashes  *HashDB
	ips     *IPDB
	domains *DomainDB
	logger  *zap.Logger

	hashLookups   atomic.Uint64
	hashMatches   atomic.Uint64
	ipLookups     atomic.Uint64
	ipMatches     atomic.Uint64
	domainLookups atomic.Uint64
	domainMatches atomic.Uint64
}

// NewMatcher creates a Matcher with empty databases ready for loading.
func NewMatcher(logger *zap.Logger) *Matcher {
	return &Matcher{
		hashes:  NewHashDB(),
		ips:     NewIPDB(),
		domains: NewDomainDB(),
		logger:  logger,
	}
}

// CheckHash looks up a file hash across all hash types.
func (m *Matcher) CheckHash(hash string) *MatchResult {
	m.hashLookups.Add(1)

	entry, found := m.hashes.Lookup(hash)
	if !found {
		return &MatchResult{Matched: false}
	}

	m.hashMatches.Add(1)
	return &MatchResult{
		Matched:       true,
		Type:          "hash",
		Indicator:     entry.Hash,
		Severity:      entry.Severity,
		Source:        entry.Source,
		Tags:          entry.Tags,
		MalwareFamily: entry.MalwareFamily,
	}
}

// CheckIP looks up an IP address against the reputation database.
func (m *Matcher) CheckIP(ip string) *MatchResult {
	m.ipLookups.Add(1)

	entry, found := m.ips.Lookup(ip)
	if !found {
		return &MatchResult{Matched: false}
	}

	m.ipMatches.Add(1)
	return &MatchResult{
		Matched:   true,
		Type:      "ip",
		Indicator: entry.Address,
		Severity:  entry.Severity,
		Source:    entry.Source,
		Tags:      entry.Tags,
	}
}

// CheckDomain looks up a domain against the reputation database.
func (m *Matcher) CheckDomain(domain string) *MatchResult {
	m.domainLookups.Add(1)

	entry, found := m.domains.Lookup(domain)
	if !found {
		return &MatchResult{Matched: false}
	}

	m.domainMatches.Add(1)
	return &MatchResult{
		Matched:   true,
		Type:      "domain",
		Indicator: entry.Domain,
		Severity:  entry.Severity,
		Source:    entry.Source,
		Tags:      entry.Tags,
	}
}

// CheckEvent inspects an event and returns all IOC matches relevant to its type.
//   - ProcessEvent: checks each hash in Hashes
//   - FileEvent: checks Hash if present
//   - NetworkEvent: checks DestIP and Domain
func (m *Matcher) CheckEvent(event interface{}) []*MatchResult {
	var results []*MatchResult

	switch ev := event.(type) {
	case *schema.ProcessEvent:
		for _, h := range ev.Hashes {
			if r := m.CheckHash(h); r.Matched {
				results = append(results, r)
			}
		}

	case schema.ProcessEvent:
		for _, h := range ev.Hashes {
			if r := m.CheckHash(h); r.Matched {
				results = append(results, r)
			}
		}

	case *schema.FileEvent:
		if ev.Hash != "" {
			if r := m.CheckHash(ev.Hash); r.Matched {
				results = append(results, r)
			}
		}

	case schema.FileEvent:
		if ev.Hash != "" {
			if r := m.CheckHash(ev.Hash); r.Matched {
				results = append(results, r)
			}
		}

	case *schema.NetworkEvent:
		if ev.DestIP != "" {
			if r := m.CheckIP(ev.DestIP); r.Matched {
				results = append(results, r)
			}
		}
		if ev.Domain != "" {
			if r := m.CheckDomain(ev.Domain); r.Matched {
				results = append(results, r)
			}
		}

	case schema.NetworkEvent:
		if ev.DestIP != "" {
			if r := m.CheckIP(ev.DestIP); r.Matched {
				results = append(results, r)
			}
		}
		if ev.Domain != "" {
			if r := m.CheckDomain(ev.Domain); r.Matched {
				results = append(results, r)
			}
		}

	default:
		m.logger.Debug("ioc: unhandled event type for IOC matching", zap.String("type", fmt.Sprintf("%T", event)))
	}

	return results
}

// LoadAll loads hash, IP, and domain databases from their respective paths.
// Empty paths are skipped.
func (m *Matcher) LoadAll(hashPath, ipPath, domainPath string) error {
	if hashPath != "" {
		if err := m.hashes.LoadFromFile(hashPath); err != nil {
			return err
		}
		m.logger.Info("loaded hash IOCs", zap.Int("count", m.hashes.Count()))
	}
	if ipPath != "" {
		if err := m.ips.LoadFromFile(ipPath); err != nil {
			return err
		}
		m.logger.Info("loaded IP IOCs", zap.Int("count", m.ips.Count()))
	}
	if domainPath != "" {
		if err := m.domains.LoadFromFile(domainPath); err != nil {
			return err
		}
		m.logger.Info("loaded domain IOCs", zap.Int("count", m.domains.Count()))
	}
	return nil
}

// Hashes returns the underlying HashDB for direct access.
func (m *Matcher) Hashes() *HashDB { return m.hashes }

// IPs returns the underlying IPDB for direct access.
func (m *Matcher) IPs() *IPDB { return m.ips }

// Domains returns the underlying DomainDB for direct access.
func (m *Matcher) Domains() *DomainDB { return m.domains }

// Stats returns a snapshot of lookup and match counters.
func (m *Matcher) Stats() MatcherStats {
	return MatcherStats{
		HashLookups:   m.hashLookups.Load(),
		HashMatches:   m.hashMatches.Load(),
		IPLookups:     m.ipLookups.Load(),
		IPMatches:     m.ipMatches.Load(),
		DomainLookups: m.domainLookups.Load(),
		DomainMatches: m.domainMatches.Load(),
	}
}
