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

// GeminiProvider implements the Provider interface for Google Gemini models
// via the generativelanguage REST API.
type GeminiProvider struct {
	apiKey  string
	model   string
	client  *http.Client
	available atomic.Bool
}

// NewGeminiProvider creates a Gemini-backed provider. projectID and location
// are reserved for future Vertex AI support and may be empty.
func NewGeminiProvider(apiKey, model, projectID, location string) *GeminiProvider {
	if model == "" {
		model = "gemini-2.5-pro"
	}
	p := &GeminiProvider{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{Timeout: 120 * time.Second},
	}
	p.available.Store(true)
	return p
}

func (p *GeminiProvider) Name() string   { return "gemini" }
func (p *GeminiProvider) Available() bool { return p.available.Load() }
func (p *GeminiProvider) Close() error   { return nil }

type geminiRequest struct {
	Contents         []geminiContent        `json:"contents"`
	SystemInstruction *geminiContent        `json:"systemInstruction,omitempty"`
	GenerationConfig  *geminiGenerationCfg  `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
	Role  string       `json:"role,omitempty"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationCfg struct {
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
	Temperature     float32 `json:"temperature,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []geminiPart `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Analyze sends a prompt to the Gemini generateContent endpoint with retry.
func (p *GeminiProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	const maxRetries = 3
	var lastErr error

	url := fmt.Sprintf(
		"https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		p.model, p.apiKey,
	)

	body := geminiRequest{
		SystemInstruction: &geminiContent{
			Parts: []geminiPart{{Text: llm.SystemPrompt}},
		},
		Contents: []geminiContent{
			{Role: "user", Parts: []geminiPart{{Text: prompt}}},
		},
		GenerationConfig: &geminiGenerationCfg{MaxOutputTokens: 4096, Temperature: 0.2},
	}

	for attempt := range maxRetries {
		payload, err := json.Marshal(body)
		if err != nil {
			return "", fmt.Errorf("gemini: marshal: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return "", fmt.Errorf("gemini: request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
			p.backoff(ctx, attempt)
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("gemini: read body: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("gemini: HTTP %d: %s", resp.StatusCode, data)
			p.backoff(ctx, attempt)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("gemini: HTTP %d: %s", resp.StatusCode, data)
		}

		var gr geminiResponse
		if err := json.Unmarshal(data, &gr); err != nil {
			return "", fmt.Errorf("gemini: unmarshal: %w", err)
		}
		if gr.Error != nil {
			return "", fmt.Errorf("gemini: %d: %s", gr.Error.Code, gr.Error.Message)
		}
		if len(gr.Candidates) > 0 && len(gr.Candidates[0].Content.Parts) > 0 {
			return gr.Candidates[0].Content.Parts[0].Text, nil
		}
		return "", fmt.Errorf("gemini: empty response")
	}

	return "", fmt.Errorf("gemini: %d retries exhausted: %w", maxRetries, lastErr)
}

func (p *GeminiProvider) backoff(ctx context.Context, attempt int) {
	d := time.Duration(1<<uint(attempt)) * time.Second
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

var _ llm.Provider = (*GeminiProvider)(nil)
