package llm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Verdict is the structured result from LLM analysis.
type Verdict struct {
	ThreatDetected    bool     `json:"threat_detected"`
	Confidence        float64  `json:"confidence"`
	ThreatType        string   `json:"threat_type"`
	Severity          string   `json:"severity"`
	MITRETechniques   []string `json:"mitre_techniques"`
	Reasoning         string   `json:"reasoning"`
	RecommendedAction string   `json:"recommended_action"`
	IOCs              []string `json:"iocs"`
	FalsePositiveRisk string   `json:"false_positive_risk"`
	AnalystNotes      string   `json:"analyst_notes"`
}

// AnalysisResult wraps a Verdict with its potential error.
type AnalysisResult struct {
	Verdict *Verdict
	Err     error
}

// EngineConfig holds configuration for the LLM engine.
type EngineConfig struct {
	Primary        Provider
	Fallback       Provider
	Local          Provider
	ForceLocal     bool
	LocalThreshold float64
	MaxConcurrent  int
}

// Engine manages LLM-based threat analysis with provider routing,
// concurrency limiting, and circuit-breaker resilience.
type Engine struct {
	primary        Provider
	fallback       Provider
	local          Provider
	forceLocal     bool
	localThreshold float64
	maxConcurrent  int
	semaphore      chan struct{}
	logger         *zap.Logger

	// circuit breaker state
	cbMu          sync.Mutex
	cbFailures    int
	cbState       cbStateType
	cbOpenUntil   time.Time
	cbThreshold   int
	cbOpenTimeout time.Duration
}

type cbStateType int

const (
	cbClosed   cbStateType = iota
	cbOpen
	cbHalfOpen
)

// NewEngine creates an Engine with primary, fallback, and local providers.
func NewEngine(cfg EngineConfig, logger *zap.Logger) (*Engine, error) {
	if cfg.Primary == nil && cfg.Local == nil {
		return nil, fmt.Errorf("llm: at least one of primary or local provider must be set")
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 4
	}
	if cfg.LocalThreshold <= 0 {
		cfg.LocalThreshold = 0.7
	}
	return &Engine{
		primary:        cfg.Primary,
		fallback:       cfg.Fallback,
		local:          cfg.Local,
		forceLocal:     cfg.ForceLocal,
		localThreshold: cfg.LocalThreshold,
		maxConcurrent:  cfg.MaxConcurrent,
		semaphore:      make(chan struct{}, cfg.MaxConcurrent),
		logger:         logger,
		cbThreshold:    5,
		cbOpenTimeout:  60 * time.Second,
	}, nil
}

// Analyze routes the event through the appropriate provider chain and returns
// a structured Verdict. It respects the concurrency semaphore and circuit
// breaker state.
func (e *Engine) Analyze(ctx context.Context, eventCtx *EventContext) (*Verdict, error) {
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	prompt := SystemPrompt + "\n\n" + BuildAnalysisPrompt(eventCtx)

	if e.forceLocal {
		return e.analyzeWith(ctx, e.local, prompt)
	}

	// Try local first when available — escalate to cloud if confidence is low.
	if e.local != nil && e.local.Available() {
		v, err := e.analyzeWith(ctx, e.local, prompt)
		if err == nil && v.Confidence >= e.localThreshold {
			return v, nil
		}
		e.logger.Debug("local analysis below threshold, escalating",
			zap.Float64("confidence", safeConfidence(v)),
			zap.Error(err))
	}

	// Cloud path with circuit breaker.
	if e.cbAllowRequest() {
		if e.primary != nil && e.primary.Available() {
			v, err := e.analyzeWith(ctx, e.primary, prompt)
			if err == nil {
				e.cbRecordSuccess()
				return v, nil
			}
			e.cbRecordFailure()
			e.logger.Warn("primary provider failed", zap.String("provider", e.primary.Name()), zap.Error(err))
		}

		if e.fallback != nil && e.fallback.Available() {
			v, err := e.analyzeWith(ctx, e.fallback, prompt)
			if err == nil {
				e.cbRecordSuccess()
				return v, nil
			}
			e.cbRecordFailure()
			e.logger.Warn("fallback provider failed", zap.String("provider", e.fallback.Name()), zap.Error(err))
		}
	} else {
		e.logger.Warn("circuit breaker open, skipping cloud providers")
	}

	// Last resort: local regardless of threshold.
	if e.local != nil && e.local.Available() {
		return e.analyzeWith(ctx, e.local, prompt)
	}

	return nil, fmt.Errorf("llm: all providers unavailable")
}

// AnalyzeAsync starts a non-blocking analysis and returns a channel that
// receives exactly one result.
func (e *Engine) AnalyzeAsync(eventCtx *EventContext) <-chan *AnalysisResult {
	ch := make(chan *AnalysisResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		v, err := e.Analyze(ctx, eventCtx)
		ch <- &AnalysisResult{Verdict: v, Err: err}
	}()
	return ch
}

func (e *Engine) analyzeWith(ctx context.Context, p Provider, prompt string) (*Verdict, error) {
	var (
		resp string
		err  error
	)
	if po, ok := p.(ProviderWithOptions); ok {
		resp, err = po.AnalyzeWithOptions(ctx, prompt, AnalyzeOptions{})
	} else {
		resp, err = p.Analyze(ctx, prompt)
	}
	if err != nil {
		return nil, fmt.Errorf("llm [%s]: %w", p.Name(), err)
	}
	return ParseVerdict(resp)
}

// Circuit breaker helpers.

func (e *Engine) cbAllowRequest() bool {
	e.cbMu.Lock()
	defer e.cbMu.Unlock()

	switch e.cbState {
	case cbClosed:
		return true
	case cbOpen:
		if time.Now().After(e.cbOpenUntil) {
			e.cbState = cbHalfOpen
			return true
		}
		return false
	case cbHalfOpen:
		return true
	}
	return true
}

func (e *Engine) cbRecordSuccess() {
	e.cbMu.Lock()
	defer e.cbMu.Unlock()
	e.cbFailures = 0
	e.cbState = cbClosed
}

func (e *Engine) cbRecordFailure() {
	e.cbMu.Lock()
	defer e.cbMu.Unlock()
	e.cbFailures++
	if e.cbFailures >= e.cbThreshold {
		e.cbState = cbOpen
		e.cbOpenUntil = time.Now().Add(e.cbOpenTimeout)
		e.logger.Warn("circuit breaker opened",
			zap.Int("failures", e.cbFailures),
			zap.Duration("open_for", e.cbOpenTimeout))
	}
}

func safeConfidence(v *Verdict) float64 {
	if v == nil {
		return 0
	}
	return v.Confidence
}

