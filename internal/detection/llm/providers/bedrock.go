package providers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/detection/llm"
)

// BedrockProvider implements the Provider interface for AWS Bedrock models
// using Signature V4 authentication.
type BedrockProvider struct {
	accessKey string
	secretKey string
	region    string
	modelID   string
	maxTokens int
	client    *http.Client
	available atomic.Bool
}

// NewBedrockProvider creates an AWS Bedrock provider. modelID is the full
// Bedrock model identifier (e.g. "anthropic.claude-3-5-sonnet-20241022-v2:0").
func NewBedrockProvider(accessKey, secretKey, region, modelID string, maxTokens int) *BedrockProvider {
	if region == "" {
		region = "us-east-1"
	}
	if modelID == "" {
		modelID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
	}
	if maxTokens <= 0 {
		maxTokens = 4096
	}
	p := &BedrockProvider{
		accessKey: accessKey,
		secretKey: secretKey,
		region:    region,
		modelID:   modelID,
		maxTokens: maxTokens,
		client:    &http.Client{Timeout: 120 * time.Second},
	}
	p.available.Store(true)
	return p
}

func (p *BedrockProvider) Name() string   { return "bedrock" }
func (p *BedrockProvider) Available() bool { return p.available.Load() }
func (p *BedrockProvider) Close() error   { return nil }

type bedrockRequest struct {
	Messages      []bedrockMsg `json:"messages"`
	System        string       `json:"system,omitempty"`
	MaxTokens     int          `json:"max_tokens"`
	AnthropicVersion string   `json:"anthropic_version"`
}

type bedrockMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type bedrockResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

// Analyze sends the prompt to AWS Bedrock with SigV4 auth and retry.
func (p *BedrockProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	const maxRetries = 3
	var lastErr error

	endpoint := fmt.Sprintf(
		"https://bedrock-runtime.%s.amazonaws.com/model/%s/invoke",
		p.region, p.modelID,
	)

	body := bedrockRequest{
		System:           llm.SystemPrompt,
		MaxTokens:        p.maxTokens,
		AnthropicVersion: "bedrock-2023-05-31",
		Messages: []bedrockMsg{
			{Role: "user", Content: prompt},
		},
	}

	for attempt := range maxRetries {
		payload, err := json.Marshal(body)
		if err != nil {
			return "", fmt.Errorf("bedrock: marshal: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return "", fmt.Errorf("bedrock: request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		p.signV4(req, payload)

		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
			p.backoff(ctx, attempt)
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("bedrock: read body: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("bedrock: HTTP %d: %s", resp.StatusCode, data)
			p.backoff(ctx, attempt)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("bedrock: HTTP %d: %s", resp.StatusCode, data)
		}

		var br bedrockResponse
		if err := json.Unmarshal(data, &br); err != nil {
			return "", fmt.Errorf("bedrock: unmarshal: %w", err)
		}
		if len(br.Content) > 0 {
			return br.Content[0].Text, nil
		}
		return "", fmt.Errorf("bedrock: empty response")
	}

	return "", fmt.Errorf("bedrock: %d retries exhausted: %w", maxRetries, lastErr)
}

// signV4 applies AWS Signature Version 4 to the request.
func (p *BedrockProvider) signV4(req *http.Request, payload []byte) {
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Host", req.URL.Host)

	payloadHash := sha256Hex(payload)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		req.Header.Get("Content-Type"), req.URL.Host, payloadHash, amzDate)
	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date"

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method, req.URL.Path, req.URL.RawQuery,
		canonicalHeaders, signedHeaders, payloadHash)

	credentialScope := fmt.Sprintf("%s/%s/bedrock/aws4_request", datestamp, p.region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate, credentialScope, sha256Hex([]byte(canonicalRequest)))

	kDate := hmacSHA256([]byte("AWS4"+p.secretKey), []byte(datestamp))
	kRegion := hmacSHA256(kDate, []byte(p.region))
	kService := hmacSHA256(kRegion, []byte("bedrock"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		p.accessKey, credentialScope, signedHeaders, signature))
}

func (p *BedrockProvider) backoff(ctx context.Context, attempt int) {
	d := time.Duration(1<<uint(attempt)) * time.Second
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

var _ llm.Provider = (*BedrockProvider)(nil)
