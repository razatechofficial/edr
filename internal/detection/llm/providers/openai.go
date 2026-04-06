package providers

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync/atomic"
	"time"

	openai "github.com/sashabaranov/go-openai"

	"github.com/razatechofficial/edr/internal/detection/llm"
)

// OpenAIProvider wraps the OpenAI ChatCompletion API (GPT-4o and compatible).
type OpenAIProvider struct {
	client      *openai.Client
	model       string
	maxTokens   int
	temperature float32
	available   atomic.Bool
}

// NewOpenAIProvider creates an OpenAI-backed provider. If baseURL is empty the
// default OpenAI endpoint is used. orgID is optional.
func NewOpenAIProvider(apiKey, model, baseURL, orgID string, maxTokens int, temperature float32) *OpenAIProvider {
	if model == "" {
		model = openai.GPT4o
	}
	if maxTokens <= 0 {
		maxTokens = 4096
	}

	cfg := openai.DefaultConfig(apiKey)
	if baseURL != "" {
		cfg.BaseURL = baseURL
	}
	if orgID != "" {
		cfg.OrgID = orgID
	}
	cfg.HTTPClient = &http.Client{Timeout: 120 * time.Second}

	p := &OpenAIProvider{
		client:      openai.NewClientWithConfig(cfg),
		model:       model,
		maxTokens:   maxTokens,
		temperature: temperature,
	}
	p.available.Store(true)
	return p
}

// Name returns the provider identifier.
func (p *OpenAIProvider) Name() string { return "openai" }

// Available reports readiness.
func (p *OpenAIProvider) Available() bool { return p.available.Load() }

// Close is a no-op for the HTTP-based client.
func (p *OpenAIProvider) Close() error { return nil }

// Analyze sends the prompt to OpenAI with retry and exponential backoff.
func (p *OpenAIProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	const maxRetries = 3
	var lastErr error

	for attempt := range maxRetries {
		resp, err := p.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
			Model:       p.model,
			MaxTokens:   p.maxTokens,
			Temperature: p.temperature,
			Messages: []openai.ChatCompletionMessage{
				{Role: openai.ChatMessageRoleSystem, Content: llm.SystemPrompt},
				{Role: openai.ChatMessageRoleUser, Content: prompt},
			},
		})
		if err == nil && len(resp.Choices) > 0 {
			return resp.Choices[0].Message.Content, nil
		}
		if err == nil {
			return "", fmt.Errorf("openai: empty response")
		}

		lastErr = err
		var apiErr *openai.APIError
		if errors.As(err, &apiErr) && apiErr.HTTPStatusCode == http.StatusTooManyRequests {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return "", ctx.Err()
			}
			continue
		}
		if attempt < maxRetries-1 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * 500 * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
	}
	return "", fmt.Errorf("openai: %d retries exhausted: %w", maxRetries, lastErr)
}

var _ llm.Provider = (*OpenAIProvider)(nil)
