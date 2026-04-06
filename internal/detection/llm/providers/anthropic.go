package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/detection/llm"
)

const anthropicAPIURL = "https://api.anthropic.com/v1/messages"

// AnthropicProvider implements the Provider interface for Claude models.
type AnthropicProvider struct {
	apiKey    string
	model     string
	maxTokens int
	client    *http.Client
	available atomic.Bool
}

// NewAnthropicProvider creates a provider targeting the Anthropic Messages API.
func NewAnthropicProvider(apiKey, model string, maxTokens int) *AnthropicProvider {
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}
	if maxTokens <= 0 {
		maxTokens = 4096
	}
	p := &AnthropicProvider{
		apiKey:    apiKey,
		model:     model,
		maxTokens: maxTokens,
		client:    &http.Client{Timeout: 120 * time.Second},
	}
	p.available.Store(true)
	return p
}

func (p *AnthropicProvider) Name() string      { return "anthropic" }
func (p *AnthropicProvider) Available() bool    { return p.available.Load() }
func (p *AnthropicProvider) Close() error       { return nil }

type anthropicRequest struct {
	Model     string            `json:"model"`
	MaxTokens int               `json:"max_tokens"`
	System    string            `json:"system,omitempty"`
	Messages  []anthropicMsg    `json:"messages"`
}

type anthropicMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Analyze sends a prompt to the Anthropic Messages API with retry logic.
func (p *AnthropicProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	const maxRetries = 3
	var lastErr error

	body := anthropicRequest{
		Model:     p.model,
		MaxTokens: p.maxTokens,
		System:    llm.SystemPrompt,
		Messages: []anthropicMsg{
			{Role: "user", Content: prompt},
		},
	}

	for attempt := range maxRetries {
		payload, err := json.Marshal(body)
		if err != nil {
			return "", fmt.Errorf("anthropic: marshal: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicAPIURL, bytes.NewReader(payload))
		if err != nil {
			return "", fmt.Errorf("anthropic: request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", p.apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")

		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
			p.backoff(ctx, attempt)
			continue
		}

		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("anthropic: read body: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("anthropic: HTTP %d: %s", resp.StatusCode, data)
			p.backoff(ctx, attempt)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("anthropic: HTTP %d: %s", resp.StatusCode, data)
		}

		var ar anthropicResponse
		if err := json.Unmarshal(data, &ar); err != nil {
			return "", fmt.Errorf("anthropic: unmarshal: %w", err)
		}
		if ar.Error != nil {
			return "", fmt.Errorf("anthropic: %s: %s", ar.Error.Type, ar.Error.Message)
		}
		for _, block := range ar.Content {
			if block.Type == "text" {
				return block.Text, nil
			}
		}
		return "", fmt.Errorf("anthropic: no text content in response")
	}

	return "", fmt.Errorf("anthropic: %d retries exhausted: %w", maxRetries, lastErr)
}

func (p *AnthropicProvider) backoff(ctx context.Context, attempt int) {
	d := time.Duration(1<<uint(attempt)) * time.Second
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

var _ llm.Provider = (*AnthropicProvider)(nil)
