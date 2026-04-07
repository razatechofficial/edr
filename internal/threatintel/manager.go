package threatintel

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/detection/ioc"
)

// ThreatIntelResult contains the outcome of an IOC lookup across all
// registered threat intelligence sources.
type ThreatIntelResult struct {
	Found         bool      `json:"found"`
	IOC           string    `json:"ioc"`
	Type          string    `json:"type"`
	Severity      string    `json:"severity"`
	Sources       []string  `json:"sources,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
	MalwareFamily string    `json:"malware_family,omitempty"`
	FirstSeen     time.Time `json:"first_seen,omitempty"`
	LastSeen      time.Time `json:"last_seen,omitempty"`
}

// Indicator is the unified representation of a threat indicator ingested from
// any feed. It is written into the IOC matcher databases.
type Indicator struct {
	Type          string    `json:"type"` // hash, ip, domain, url
	Value         string    `json:"value"`
	Severity      string    `json:"severity"`
	Source        string    `json:"source"`
	Tags          []string  `json:"tags,omitempty"`
	MalwareFamily string    `json:"malware_family,omitempty"`
	FirstSeen     time.Time `json:"first_seen,omitempty"`
	LastSeen      time.Time `json:"last_seen,omitempty"`
}

// Feed is the interface implemented by all threat intelligence sources
// (MISP, OTX, generic STIX/TAXII, etc.).
type Feed interface {
	Name() string
	Fetch(ctx context.Context, since time.Time) ([]Indicator, error)
}

// Manager orchestrates all threat intelligence sources, coordinating periodic
// updates and unified IOC lookups.
type Manager struct {
	matcher *ioc.Matcher
	logger  *zap.Logger

	mu    sync.RWMutex
	feeds []Feed
	seen  map[string]time.Time
	conf  map[string]float64

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewManager creates a Manager that writes discovered IOCs into the given matcher.
func NewManager(matcher *ioc.Matcher, logger *zap.Logger) *Manager {
	return &Manager{
		matcher: matcher,
		logger:  logger,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
		seen:    make(map[string]time.Time),
		conf: map[string]float64{
			"misp":       0.95,
			"cisa":       0.9,
			"otx":        0.7,
			"abuse.ch":   0.85,
			"spamhaus":   0.85,
			"torproject": 0.75,
		},
	}
}

// RegisterFeed adds a threat intelligence feed to the manager.
func (m *Manager) RegisterFeed(feed Feed) {
	m.mu.Lock()
	m.feeds = append(m.feeds, feed)
	m.mu.Unlock()
}

// Start begins background feed update goroutines.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.RLock()
	feeds := make([]Feed, len(m.feeds))
	copy(feeds, m.feeds)
	m.mu.RUnlock()

	if len(feeds) == 0 {
		m.logger.Warn("threatintel: no feeds registered")
	}

	for _, f := range feeds {
		if err := m.initialFetch(ctx, f); err != nil {
			m.logger.Error("initial feed fetch failed",
				zap.String("feed", f.Name()),
				zap.Error(err),
			)
		}
	}

	go m.run(ctx)
	return nil
}

// Stop terminates all background updaters.
func (m *Manager) Stop() error {
	m.stopOnce.Do(func() {
		close(m.stopCh)
		<-m.doneCh
	})
	return nil
}

// LookupIOC queries the IOC matcher for a given indicator string.
func (m *Manager) LookupIOC(value string) (*ThreatIntelResult, error) {
	if value == "" {
		return nil, fmt.Errorf("threatintel: empty IOC value")
	}

	if r := m.matcher.CheckHash(value); r.Matched {
		return &ThreatIntelResult{
			Found:         true,
			IOC:           value,
			Type:          "hash",
			Severity:      r.Severity,
			Sources:       []string{r.Source},
			Tags:          r.Tags,
			MalwareFamily: r.MalwareFamily,
		}, nil
	}

	if r := m.matcher.CheckIP(value); r.Matched {
		return &ThreatIntelResult{
			Found:    true,
			IOC:      value,
			Type:     "ip",
			Severity: r.Severity,
			Sources:  []string{r.Source},
			Tags:     r.Tags,
		}, nil
	}

	if r := m.matcher.CheckDomain(value); r.Matched {
		return &ThreatIntelResult{
			Found:    true,
			IOC:      value,
			Type:     "domain",
			Severity: r.Severity,
			Sources:  []string{r.Source},
			Tags:     r.Tags,
		}, nil
	}

	return &ThreatIntelResult{Found: false, IOC: value}, nil
}

func (m *Manager) initialFetch(ctx context.Context, feed Feed) error {
	since := time.Now().Add(-24 * time.Hour)
	indicators, err := feed.Fetch(ctx, since)
	if err != nil {
		return err
	}
	m.ingestIndicators(feed.Name(), indicators)
	return nil
}

func (m *Manager) run(ctx context.Context) {
	defer close(m.doneCh)
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.refreshAll(ctx)
		}
	}
}

func (m *Manager) refreshAll(ctx context.Context) {
	m.mu.RLock()
	feeds := make([]Feed, len(m.feeds))
	copy(feeds, m.feeds)
	m.mu.RUnlock()

	since := time.Now().Add(-2 * time.Hour)
	for _, f := range feeds {
		indicators, err := f.Fetch(ctx, since)
		if err != nil {
			m.logger.Error("feed refresh failed",
				zap.String("feed", f.Name()),
				zap.Error(err),
			)
			continue
		}
		m.ingestIndicators(f.Name(), indicators)
	}
}

func (m *Manager) ingestIndicators(source string, indicators []Indicator) {
	var added int
	now := time.Now()
	for _, ind := range indicators {
		key := strings.ToLower(ind.Type + ":" + ind.Value + ":" + source)
		ttl := 24 * time.Hour
		if ind.Type == "ip" {
			ttl = 6 * time.Hour
		}
		if ind.Type == "domain" {
			ttl = 12 * time.Hour
		}
		m.mu.Lock()
		if exp, ok := m.seen[key]; ok && now.Before(exp) {
			m.mu.Unlock()
			continue
		}
		m.seen[key] = now.Add(ttl)
		m.mu.Unlock()
		sev := normalizeSeverity(ind.Severity, m.confidence(source))
		switch ind.Type {
		case "hash":
			hashType := ioc.HashSHA256
			switch {
			case len(ind.Value) == 32:
				hashType = ioc.HashMD5
			case len(ind.Value) == 40:
				hashType = ioc.HashSHA1
			}
			m.matcher.Hashes().Add(ioc.HashEntry{
				Hash:          ind.Value,
				Type:          hashType,
				MalwareFamily: ind.MalwareFamily,
				Source:        source,
				Severity:      sev,
				Tags:          ind.Tags,
			})
			added++
		case "ip":
			m.matcher.IPs().Add(ioc.IPEntry{
				Address:  ind.Value,
				Source:   source,
				Severity: sev,
				Tags:     ind.Tags,
			})
			added++
		case "domain":
			m.matcher.Domains().Add(ioc.DomainEntry{
				Domain:   ind.Value,
				Source:   source,
				Severity: sev,
				Tags:     ind.Tags,
			})
			added++
		}
	}
	if added > 0 {
		m.logger.Info("ingested indicators",
			zap.String("source", source),
			zap.Int("count", added),
		)
	}
}

func (m *Manager) confidence(source string) float64 {
	s := strings.ToLower(source)
	for k, v := range m.conf {
		if strings.Contains(s, k) {
			return v
		}
	}
	return 0.6
}

func normalizeSeverity(sev string, confidence float64) string {
	s := strings.ToLower(strings.TrimSpace(sev))
	if s == "" {
		if confidence >= 0.9 {
			return "high"
		}
		if confidence >= 0.75 {
			return "medium"
		}
		return "low"
	}
	if confidence < 0.7 && s == "critical" {
		return "high"
	}
	return s
}
