package llm

import (
	"context"
	"time"
)

// Provider is the interface all LLM providers implement.
type Provider interface {
	// Name returns the human-readable provider identifier.
	Name() string
	// Analyze sends a prompt and returns the raw LLM response.
	Analyze(ctx context.Context, prompt string) (string, error)
	// Available reports whether the provider is reachable and configured.
	Available() bool
	// Close releases any resources held by the provider.
	Close() error
}

// AnalyzeOptions carries optional provider tuning knobs.
type AnalyzeOptions struct {
	Model       string
	MaxTokens   int
	Temperature float32
	Timeout     time.Duration
}

// ProviderWithOptions is optionally implemented by providers that support
// model/tuning controls per request.
type ProviderWithOptions interface {
	Provider
	AnalyzeWithOptions(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error)
}

// EventContext contains all the context for LLM analysis of a security event.
type EventContext struct {
	Event                 interface{}
	ProcessTree           []ProcessInfo
	RecentFiles           []string
	RecentConnections     []string
	RecentRegistryChanges []string
	SimilarHistorical     []interface{}
	ThreatIntelContext     []string
	BehavioralIndicators   []string
	Model                  string
	MaxTokens              int
	Temperature            float32
	Timeout                time.Duration
}

// ProcessInfo describes a single process in a process tree.
type ProcessInfo struct {
	PID  uint32
	PPID uint32
	Name string
	Path string
	Args string
	User string
}
