package providers

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	openai "github.com/sashabaranov/go-openai"

	"github.com/razatechofficial/edr/internal/detection/llm"
)

const defaultGroqBaseURL = "https://api.groq.com/openai/v1"

// GroqProvider implements the Provider interface using the Groq inference API.
// Groq hosts open-source models (Llama, Mixtral, etc.) and uses an
// OpenAI-compatible REST API at api.groq.com.
type GroqProvider struct {
	client    *openai.Client
	model     string
	maxTokens int
	available atomic.Bool

	mu          sync.Mutex
	failures    int
	cbOpen      bool
	cbOpenUntil time.Time

	// rate limiter: simple token-bucket per minute
	rlMu       sync.Mutex
	rlLast     time.Time
	rlInterval time.Duration
}

func NewGroqProvider(apiKey, model, baseURL string, maxTokens int) *GroqProvider {
	if model == "" {
		model = "llama-3.1-8b-instant"
	}
	if baseURL == "" {
		baseURL = defaultGroqBaseURL
	}
	if maxTokens <= 0 {
		maxTokens = 1024
	}

	cfg := openai.DefaultConfig(apiKey)
	cfg.BaseURL = baseURL
	cfg.HTTPClient = &http.Client{Timeout: 60 * time.Second}

	p := &GroqProvider{
		client:     openai.NewClientWithConfig(cfg),
		model:      model,
		maxTokens:  maxTokens,
		rlInterval: 20 * time.Second,
	}
	p.available.Store(true)
	return p
}

func (p *GroqProvider) Name() string   { return "groq" }
func (p *GroqProvider) Available() bool { return p.available.Load() && p.cbAllowed() }
func (p *GroqProvider) Close() error   { return nil }

func (p *GroqProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	if !p.cbAllowed() {
		return "", fmt.Errorf("groq: circuit breaker open")
	}

	p.waitRateLimit(ctx)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	resp, err := p.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:     p.model,
		MaxTokens: p.maxTokens,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
	})
	if err != nil {
		p.cbRecord()
		return "", fmt.Errorf("groq: %w", err)
	}
	if len(resp.Choices) == 0 {
		p.cbRecord()
		return "", fmt.Errorf("groq: empty response")
	}

	p.cbReset()
	return resp.Choices[0].Message.Content, nil
}

func (p *GroqProvider) waitRateLimit(ctx context.Context) {
	p.rlMu.Lock()
	wait := time.Until(p.rlLast.Add(p.rlInterval))
	if wait > 0 {
		p.rlLast = p.rlLast.Add(p.rlInterval)
	} else {
		p.rlLast = time.Now()
	}
	p.rlMu.Unlock()

	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
	}
}

func (p *GroqProvider) cbAllowed() bool {
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

func (p *GroqProvider) cbRecord() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures++
	if p.failures >= 5 {
		p.cbOpen = true
		p.cbOpenUntil = time.Now().Add(60 * time.Second)
	}
}

func (p *GroqProvider) cbReset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures = 0
	p.cbOpen = false
}

var _ llm.Provider = (*GroqProvider)(nil)
