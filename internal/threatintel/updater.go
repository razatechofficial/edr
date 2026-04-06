package threatintel

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/detection/ioc"
)

// Updater periodically refreshes threat intelligence feeds and writes new IOCs
// into the matcher databases. It deduplicates indicators before ingestion.
type Updater struct {
	feeds   []Feed
	matcher *ioc.Matcher
	logger  *zap.Logger

	mu         sync.RWMutex
	seen       map[string]struct{} // dedup key -> struct{}
	lastUpdate time.Time

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewUpdater creates an Updater that writes into the given IOC matcher.
func NewUpdater(feeds []Feed, matcher *ioc.Matcher, logger *zap.Logger) *Updater {
	return &Updater{
		feeds:   feeds,
		matcher: matcher,
		logger:  logger,
		seen:    make(map[string]struct{}),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

// Start begins the periodic feed refresh loop. An initial fetch is performed
// synchronously before the background goroutine takes over.
func (u *Updater) Start(ctx context.Context, interval time.Duration) error {
	u.refreshAll(ctx)
	go u.loop(ctx, interval)
	return nil
}

// Stop terminates the background refresh loop.
func (u *Updater) Stop() {
	u.stopOnce.Do(func() {
		close(u.stopCh)
		<-u.doneCh
	})
}

// LastUpdate returns the timestamp of the most recent successful refresh.
func (u *Updater) LastUpdate() time.Time {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.lastUpdate
}

func (u *Updater) loop(ctx context.Context, interval time.Duration) {
	defer close(u.doneCh)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-u.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.refreshAll(ctx)
		}
	}
}

func (u *Updater) refreshAll(ctx context.Context) {
	u.mu.RLock()
	since := u.lastUpdate
	u.mu.RUnlock()

	if since.IsZero() {
		since = time.Now().Add(-24 * time.Hour)
	}

	var totalNew int
	for _, feed := range u.feeds {
		select {
		case <-ctx.Done():
			return
		default:
		}

		indicators, err := feed.Fetch(ctx, since)
		if err != nil {
			u.logger.Error("updater: feed fetch failed",
				zap.String("feed", feed.Name()),
				zap.Error(err),
			)
			continue
		}

		newInds := u.dedup(indicators)
		u.ingest(feed.Name(), newInds)
		totalNew += len(newInds)

		u.logger.Debug("updater: feed refreshed",
			zap.String("feed", feed.Name()),
			zap.Int("fetched", len(indicators)),
			zap.Int("new", len(newInds)),
		)
	}

	u.mu.Lock()
	u.lastUpdate = time.Now()
	u.mu.Unlock()

	if totalNew > 0 {
		u.logger.Info("updater: refresh complete", zap.Int("new_indicators", totalNew))
	}
}

func (u *Updater) dedup(indicators []Indicator) []Indicator {
	u.mu.Lock()
	defer u.mu.Unlock()

	var unique []Indicator
	for _, ind := range indicators {
		key := ind.Type + ":" + ind.Value
		if _, exists := u.seen[key]; exists {
			continue
		}
		u.seen[key] = struct{}{}
		unique = append(unique, ind)
	}
	return unique
}

func (u *Updater) ingest(source string, indicators []Indicator) {
	for _, ind := range indicators {
		switch ind.Type {
		case "hash":
			hashType := ioc.HashSHA256
			switch {
			case len(ind.Value) == 32:
				hashType = ioc.HashMD5
			case len(ind.Value) == 40:
				hashType = ioc.HashSHA1
			}
			u.matcher.Hashes().Add(ioc.HashEntry{
				Hash:          ind.Value,
				Type:          hashType,
				MalwareFamily: ind.MalwareFamily,
				Source:        source,
				Severity:      ind.Severity,
				Tags:          ind.Tags,
			})
		case "ip":
			u.matcher.IPs().Add(ioc.IPEntry{
				Address:  ind.Value,
				Source:   source,
				Severity: ind.Severity,
				Tags:     ind.Tags,
			})
		case "domain":
			u.matcher.Domains().Add(ioc.DomainEntry{
				Domain:   ind.Value,
				Source:   source,
				Severity: ind.Severity,
				Tags:     ind.Tags,
			})
		}
	}
}
