package rag

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

// EmbedderMode selects the embedding backend.
type EmbedderMode int

const (
	// EmbedLocal uses TF-IDF/BM25 for air-gapped environments.
	EmbedLocal EmbedderMode = iota
	// EmbedOpenAI uses the OpenAI embeddings API.
	EmbedOpenAI
	// EmbedSecBERT uses a locally-served SecBERT ONNX model for semantic
	// embeddings in air-gapped deployments. This replaces TF-IDF with
	// transformer-based embeddings that understand security domain vocabulary.
	EmbedSecBERT
)

// SecBERTSession abstracts ONNX-based SecBERT inference so the embedder
// doesn't depend directly on the ml package (avoids circular imports).
type SecBERTSession interface {
	EmbedText(text string) ([]float32, error)
	Dimension() int
	Close()
}

// Embedder generates fixed-dimension text embeddings via a local algorithm or
// cloud API.
type Embedder struct {
	mode       EmbedderMode
	apiKey     string
	model      string
	dimension  int
	client     *http.Client

	// local mode vocabulary built from indexed documents
	vocab map[string]int
	idf   []float64
	docs  int

	// SecBERT mode: ONNX session for transformer embeddings
	secbert SecBERTSession
}

// NewEmbedder creates an Embedder. For EmbedLocal, apiKey/model are ignored.
// dimension controls the output vector size for local mode (default 512).
func NewEmbedder(mode EmbedderMode, apiKey, model string, dimension int) *Embedder {
	if model == "" {
		model = "text-embedding-3-small"
	}
	if dimension <= 0 {
		dimension = 512
	}
	return &Embedder{
		mode:      mode,
		apiKey:    apiKey,
		model:     model,
		dimension: dimension,
		client:    &http.Client{Timeout: 30 * time.Second},
		vocab:     make(map[string]int),
	}
}

// SetSecBERT configures the SecBERT ONNX session for transformer embeddings.
func (e *Embedder) SetSecBERT(session SecBERTSession) {
	e.secbert = session
	if session != nil {
		e.dimension = session.Dimension()
	}
}

// Embed returns a vector representation of text.
func (e *Embedder) Embed(ctx context.Context, text string) ([]float32, error) {
	switch e.mode {
	case EmbedOpenAI:
		return e.embedOpenAI(ctx, text)
	case EmbedSecBERT:
		return e.embedSecBERT(text)
	default:
		return e.embedLocal(text), nil
	}
}

func (e *Embedder) embedSecBERT(text string) ([]float32, error) {
	if e.secbert == nil {
		return e.embedLocal(text), nil
	}
	return e.secbert.EmbedText(text)
}

// TrainLocal updates the local TF-IDF vocabulary with a new document.
func (e *Embedder) TrainLocal(text string) {
	tokens := tokenize(text)
	seen := make(map[string]bool)
	for _, t := range tokens {
		if _, ok := e.vocab[t]; !ok {
			e.vocab[t] = len(e.vocab)
		}
		seen[t] = true
	}
	e.docs++

	// Recompute IDF lazily — acceptable for incremental indexing at startup.
	e.idf = make([]float64, len(e.vocab))
	for i := range e.idf {
		e.idf[i] = 1.0
	}
	for t := range seen {
		idx := e.vocab[t]
		if idx < len(e.idf) {
			e.idf[idx] = math.Log(float64(e.docs+1) / (e.idf[idx] + 1))
		}
	}
}

func (e *Embedder) embedLocal(text string) []float32 {
	tokens := tokenize(text)
	tf := make(map[string]float64)
	for _, t := range tokens {
		tf[t]++
	}
	for k := range tf {
		tf[k] /= float64(len(tokens))
	}

	vec := make([]float32, e.dimension)
	for tok, freq := range tf {
		idx, ok := e.vocab[tok]
		if !ok {
			continue
		}
		bucket := idx % e.dimension
		idfVal := 1.0
		if idx < len(e.idf) {
			idfVal = e.idf[idx]
		}
		vec[bucket] += float32(freq * idfVal)
	}

	// L2-normalize
	var norm float64
	for _, v := range vec {
		norm += float64(v) * float64(v)
	}
	if norm > 0 {
		norm = math.Sqrt(norm)
		for i := range vec {
			vec[i] = float32(float64(vec[i]) / norm)
		}
	}
	return vec
}

type openAIEmbedRequest struct {
	Input string `json:"input"`
	Model string `json:"model"`
}

type openAIEmbedResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (e *Embedder) embedOpenAI(ctx context.Context, text string) ([]float32, error) {
	payload, err := json.Marshal(openAIEmbedRequest{Input: text, Model: e.model})
	if err != nil {
		return nil, fmt.Errorf("embedder: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.openai.com/v1/embeddings", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("embedder: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.apiKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embedder: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("embedder: read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embedder: HTTP %d: %s", resp.StatusCode, data)
	}

	var result openAIEmbedResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("embedder: unmarshal: %w", err)
	}
	if result.Error != nil {
		return nil, fmt.Errorf("embedder: %s", result.Error.Message)
	}
	if len(result.Data) == 0 || len(result.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("embedder: empty embedding")
	}
	return result.Data[0].Embedding, nil
}

func tokenize(text string) []string {
	text = strings.ToLower(text)
	var tokens []string
	for _, word := range strings.Fields(text) {
		word = strings.Trim(word, ".,;:!?()[]{}\"'`")
		if len(word) > 1 {
			tokens = append(tokens, word)
		}
	}
	return tokens
}
