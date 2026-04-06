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

// OllamaProvider implements the Provider interface for local Ollama instances.
type OllamaProvider struct {
	endpoint  string
	model     string
	keepAlive string
	numCtx    int
	numGPU    int
	numThread int
	client    *http.Client
	available atomic.Bool
}

// NewOllamaProvider creates a provider targeting a local Ollama server.
// endpoint defaults to "http://localhost:11434" if empty.
func NewOllamaProvider(endpoint, model, keepAlive string, numCtx, numGPU, numThread int) *OllamaProvider {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3"
	}
	if keepAlive == "" {
		keepAlive = "5m"
	}
	if numCtx <= 0 {
		numCtx = 8192
	}
	p := &OllamaProvider{
		endpoint:  endpoint,
		model:     model,
		keepAlive: keepAlive,
		numCtx:    numCtx,
		numGPU:    numGPU,
		numThread: numThread,
		client:    &http.Client{Timeout: 5 * time.Minute},
	}
	p.available.Store(true)
	return p
}

func (p *OllamaProvider) Name() string { return "ollama" }
func (p *OllamaProvider) Close() error { return nil }

// Available checks whether the Ollama server is reachable.
func (p *OllamaProvider) Available() bool {
	if !p.available.Load() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+"/api/tags", nil)
	if err != nil {
		return false
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type ollamaRequest struct {
	Model     string            `json:"model"`
	Prompt    string            `json:"prompt"`
	System    string            `json:"system,omitempty"`
	Stream    bool              `json:"stream"`
	KeepAlive string            `json:"keep_alive,omitempty"`
	Options   *ollamaOptions    `json:"options,omitempty"`
}

type ollamaOptions struct {
	NumCtx    int `json:"num_ctx,omitempty"`
	NumGPU    int `json:"num_gpu,omitempty"`
	NumThread int `json:"num_thread,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error,omitempty"`
}

// Analyze sends a prompt to the local Ollama generate endpoint.
func (p *OllamaProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	body := ollamaRequest{
		Model:     p.model,
		Prompt:    prompt,
		System:    llm.SystemPrompt,
		Stream:    false,
		KeepAlive: p.keepAlive,
		Options: &ollamaOptions{
			NumCtx:    p.numCtx,
			NumGPU:    p.numGPU,
			NumThread: p.numThread,
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("ollama: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/api/generate", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("ollama: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("ollama: read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama: HTTP %d: %s", resp.StatusCode, data)
	}

	var or ollamaResponse
	if err := json.Unmarshal(data, &or); err != nil {
		return "", fmt.Errorf("ollama: unmarshal: %w", err)
	}
	if or.Error != "" {
		return "", fmt.Errorf("ollama: %s", or.Error)
	}
	return or.Response, nil
}

var _ llm.Provider = (*OllamaProvider)(nil)
