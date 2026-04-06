package providers

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sync/atomic"
	"time"

	openai "github.com/sashabaranov/go-openai"

	"github.com/razatechofficial/edr/internal/detection/llm"
)

// AzureProvider implements the Provider interface for Azure OpenAI Service
// deployments.
type AzureProvider struct {
	client     *openai.Client
	model      string
	maxTokens  int
	available  atomic.Bool
}

// NewAzureProvider creates a provider that uses Azure OpenAI. The endpoint is
// the Azure resource URL (e.g. https://<resource>.openai.azure.com), model is
// the deployment name, and apiVersion defaults to "2024-06-01" if empty.
func NewAzureProvider(apiKey, endpoint, model, apiVersion string, maxTokens int) *AzureProvider {
	if apiVersion == "" {
		apiVersion = "2024-06-01"
	}
	if maxTokens <= 0 {
		maxTokens = 4096
	}

	cfg := openai.DefaultAzureConfig(apiKey, endpoint)
	cfg.APIVersion = apiVersion
	cfg.HTTPClient = &http.Client{Timeout: 120 * time.Second}

	p := &AzureProvider{
		client:    openai.NewClientWithConfig(cfg),
		model:     model,
		maxTokens: maxTokens,
	}
	p.available.Store(true)
	return p
}

func (p *AzureProvider) Name() string   { return "azure-openai" }
func (p *AzureProvider) Available() bool { return p.available.Load() }
func (p *AzureProvider) Close() error   { return nil }

// Analyze sends the prompt to Azure OpenAI with retry and backoff.
func (p *AzureProvider) Analyze(ctx context.Context, prompt string) (string, error) {
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
			return resp.Choices[0].Message.Content, nil
		}
		if err == nil {
			lastErr = fmt.Errorf("azure: empty response")
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

	return "", fmt.Errorf("azure: %d retries exhausted: %w", maxRetries, lastErr)
}

var _ llm.Provider = (*AzureProvider)(nil)
