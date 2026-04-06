package comms

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Policy represents the agent configuration received from the control-plane.
type Policy struct {
	Version    string          `json:"version"`
	UpdatedAt  time.Time       `json:"updated_at"`
	Detection  DetectionPolicy `json:"detection"`
	Response   ResponsePolicy  `json:"response"`
	Collection CollectionPolicy `json:"collection"`
	RawJSON    json.RawMessage `json:"raw,omitempty"`
}

// DetectionPolicy configures which detection engines and rules are active.
type DetectionPolicy struct {
	SigmaEnabled      bool     `json:"sigma_enabled"`
	YARAEnabled       bool     `json:"yara_enabled"`
	IOCEnabled        bool     `json:"ioc_enabled"`
	BehavioralEnabled bool     `json:"behavioral_enabled"`
	MLEnabled         bool     `json:"ml_enabled"`
	LLMEnabled        bool     `json:"llm_enabled"`
	EnabledRuleIDs    []string `json:"enabled_rule_ids,omitempty"`
	DisabledRuleIDs   []string `json:"disabled_rule_ids,omitempty"`
}

// ResponsePolicy controls automated response capabilities.
type ResponsePolicy struct {
	AutoResponse    bool `json:"auto_response"`
	KillProcess     bool `json:"kill_process"`
	QuarantineFile  bool `json:"quarantine_file"`
	NetworkIsolate  bool `json:"network_isolate"`
	CollectForensic bool `json:"collect_forensics"`
}

// CollectionPolicy specifies what telemetry to collect.
type CollectionPolicy struct {
	ProcessEvents bool `json:"process_events"`
	FileEvents    bool `json:"file_events"`
	NetworkEvents bool `json:"network_events"`
	AuthEvents    bool `json:"auth_events"`
	DNSEvents     bool `json:"dns_events"`
	RegistryEvents bool `json:"registry_events"`
}

// PolicyFetcher retrieves the current policy from the control-plane.
type PolicyFetcher interface {
	FetchPolicy(ctx context.Context) ([]byte, error)
}

// PolicySync manages periodic policy synchronisation with the server.
type PolicySync struct {
	fetcher PolicyFetcher
	logger  *zap.Logger

	mu     sync.RWMutex
	policy *Policy

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewPolicySync creates a PolicySync with the given fetcher.
func NewPolicySync(fetcher PolicyFetcher, logger *zap.Logger) *PolicySync {
	return &PolicySync{
		fetcher: fetcher,
		logger:  logger,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

// Sync fetches the latest policy from the server.
func (ps *PolicySync) Sync(ctx context.Context) (*Policy, error) {
	data, err := ps.fetcher.FetchPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy_sync: fetch: %w", err)
	}

	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy_sync: unmarshal: %w", err)
	}
	p.RawJSON = data

	ps.mu.Lock()
	ps.policy = &p
	ps.mu.Unlock()

	ps.logger.Info("policy synced", zap.String("version", p.Version))
	return &p, nil
}

// Current returns the last-synced policy or nil if none has been fetched.
func (ps *PolicySync) Current() *Policy {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.policy
}

// Start begins periodic policy syncing at the specified interval.
func (ps *PolicySync) Start(ctx context.Context, interval time.Duration) error {
	if _, err := ps.Sync(ctx); err != nil {
		ps.logger.Warn("initial policy sync failed", zap.Error(err))
	}

	go ps.loop(ctx, interval)
	return nil
}

// Stop terminates the periodic sync loop.
func (ps *PolicySync) Stop() {
	ps.stopOnce.Do(func() {
		close(ps.stopCh)
		<-ps.doneCh
	})
}

func (ps *PolicySync) loop(ctx context.Context, interval time.Duration) {
	defer close(ps.doneCh)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ps.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := ps.Sync(ctx); err != nil {
				ps.logger.Error("policy sync failed", zap.Error(err))
			}
		}
	}
}
