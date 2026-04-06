package providers

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	openai "github.com/sashabaranov/go-openai"

	"github.com/razatechofficial/edr/internal/detection/llm"
)

const defaultGrokBaseURL = "https://api.x.ai/v1"

// GrokProvider implements the Provider interface for xAI Grok models via the
// OpenAI-compatible API at api.x.ai.
type GrokProvider struct {
	client    *openai.Client
	model     string
	maxTokens int
	available atomic.Bool

	// circuit breaker
	mu          sync.Mutex
	failures    int
	cbOpen      bool
	cbOpenUntil time.Time
}

// NewGrokProvider creates a Grok-backed provider. If baseURL is empty, the
// default xAI endpoint is used.
func NewGrokProvider(apiKey, model, baseURL string, maxTokens int) *GrokProvider {
	if model == "" {
		model = "grok-3"
	}
	if baseURL == "" {
		baseURL = defaultGrokBaseURL
	}
	if maxTokens <= 0 {
		maxTokens = 4096
	}

	cfg := openai.DefaultConfig(apiKey)
	cfg.BaseURL = baseURL
	cfg.HTTPClient = &http.Client{Timeout: 120 * time.Second}

	p := &GrokProvider{
		client:    openai.NewClientWithConfig(cfg),
		model:     model,
		maxTokens: maxTokens,
	}
	p.available.Store(true)
	return p
}

func (p *GrokProvider) Name() string   { return "grok" }
func (p *GrokProvider) Available() bool { return p.available.Load() && p.cbAllowed() }
func (p *GrokProvider) Close() error   { return nil }

// Analyze sends the prompt to the Grok API with retry and circuit breaker.
func (p *GrokProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	if !p.cbAllowed() {
		return "", fmt.Errorf("grok: circuit breaker open")
	}

	const maxRetries = 3
	var lastErr error

	for attempt := range maxRetries {
		resp, err := p.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
			Model:     p.model,
			MaxTokens: p.maxTokens,
			Messages: []openai.ChatCompletionMessage{
				{Role: openai.ChatMessageRoleSystem, Content: llm.SystemPrompt},
				{Role: openai.ChatMessageRoleUser, Content: prompt},
			},
		})
		if err == nil && len(resp.Choices) > 0 {
			p.cbReset()
			return resp.Choices[0].Message.Content, nil
		}
		if err == nil {
			lastErr = fmt.Errorf("grok: empty response")
		} else {
			lastErr = err
		}

		backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	p.cbRecord()
	return "", fmt.Errorf("grok: %d retries exhausted: %w", maxRetries, lastErr)
}

func (p *GrokProvider) cbAllowed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cbOpen {
		return true
	}
	if time.Now().After(p.cbOpenUntil) {
		p.cbOpen = false
		p.failures = 0
		return true
	}
	return false
}

func (p *GrokProvider) cbRecord() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures++
	if p.failures >= 5 {
		p.cbOpen = true
		p.cbOpenUntil = time.Now().Add(60 * time.Second)
	}
}

func (p *GrokProvider) cbReset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures = 0
	p.cbOpen = false
}

var _ llm.Provider = (*GrokProvider)(nil)
