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

// LlamaCppProvider implements the Provider interface for a local llama.cpp
// HTTP server (the --server mode).
type LlamaCppProvider struct {
	endpoint  string
	ctxSize   int
	nGPULayers int
	client    *http.Client
	available atomic.Bool
}

// NewLlamaCppProvider creates a provider targeting a llama.cpp server.
// endpoint defaults to "http://localhost:8080" if empty.
func NewLlamaCppProvider(endpoint string, ctxSize, nGPULayers int) *LlamaCppProvider {
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}
	if ctxSize <= 0 {
		ctxSize = 8192
	}
	p := &LlamaCppProvider{
		endpoint:   endpoint,
		ctxSize:    ctxSize,
		nGPULayers: nGPULayers,
		client:     &http.Client{Timeout: 5 * time.Minute},
	}
	p.available.Store(true)
	return p
}

func (p *LlamaCppProvider) Name() string { return "llamacpp" }
func (p *LlamaCppProvider) Close() error { return nil }

// Available checks whether the llama.cpp server is reachable.
func (p *LlamaCppProvider) Available() bool {
	if !p.available.Load() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+"/health", nil)
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

type llamaCppRequest struct {
	Prompt      string  `json:"prompt"`
	NPredict    int     `json:"n_predict,omitempty"`
	Temperature float32 `json:"temperature,omitempty"`
	NCtx        int     `json:"n_ctx,omitempty"`
	NGPULayers  int     `json:"n_gpu_layers,omitempty"`
	Stream      bool    `json:"stream"`
}

type llamaCppResponse struct {
	Content string `json:"content"`
	Stop    bool   `json:"stop"`
}

// Analyze sends a prompt to the llama.cpp /completion endpoint.
func (p *LlamaCppProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	fullPrompt := fmt.Sprintf("[INST] <<SYS>>\n%s\n<</SYS>>\n\n%s [/INST]", llm.SystemPrompt, prompt)

	body := llamaCppRequest{
		Prompt:      fullPrompt,
		NPredict:    4096,
		Temperature: 0.2,
		NCtx:        p.ctxSize,
		NGPULayers:  p.nGPULayers,
		Stream:      false,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("llamacpp: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/completion", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("llamacpp: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("llamacpp: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("llamacpp: read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llamacpp: HTTP %d: %s", resp.StatusCode, data)
	}

	var lr llamaCppResponse
	if err := json.Unmarshal(data, &lr); err != nil {
		return "", fmt.Errorf("llamacpp: unmarshal: %w", err)
	}
	return lr.Content, nil
}

var _ llm.Provider = (*LlamaCppProvider)(nil)
