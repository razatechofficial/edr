package rag

import (
	"context"
	"fmt"
	"runtime"

	chromem "github.com/philippgille/chromem-go"
)

// Chunk represents a retrieved text chunk with metadata and relevance score.
type Chunk struct {
	ID       string
	Text     string
	Metadata map[string]string
	Score    float32
}

// VectorDB is a local vector store backed by chromem-go.
type VectorDB struct {
	db         *chromem.DB
	collection *chromem.Collection
}

// NewVectorDB opens or creates a persistent vector database at path.
func NewVectorDB(path string) (*VectorDB, error) {
	db, err := chromem.NewPersistentDB(path, false)
	if err != nil {
		return nil, fmt.Errorf("vectordb: open: %w", err)
	}

	col, err := db.GetOrCreateCollection("edr_knowledge", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("vectordb: collection: %w", err)
	}

	return &VectorDB{db: db, collection: col}, nil
}

// Add inserts a document chunk into the vector store. The embedding function
// is provided at query/add time via chromem's built-in handling when nil
// embeddings are supplied, but here we pass pre-computed embeddings.
func (v *VectorDB) Add(ctx context.Context, id, text string, embedding []float32, metadata map[string]string) error {
	doc := chromem.Document{
		ID:        id,
		Content:   text,
		Metadata:  metadata,
		Embedding: embedding,
	}
	if err := v.collection.AddDocuments(ctx, []chromem.Document{doc}, runtime.NumCPU()); err != nil {
		return fmt.Errorf("vectordb: add: %w", err)
	}
	return nil
}

// Query finds the topK most similar chunks to the given embedding.
func (v *VectorDB) Query(ctx context.Context, embedding []float32, topK int) ([]Chunk, error) {
	if topK <= 0 {
		topK = 5
	}
	results, err := v.collection.QueryEmbedding(ctx, embedding, topK, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("vectordb: query: %w", err)
	}

	chunks := make([]Chunk, 0, len(results))
	for _, r := range results {
		chunks = append(chunks, Chunk{
			ID:       r.ID,
			Text:     r.Content,
			Metadata: r.Metadata,
			Score:    r.Similarity,
		})
	}
	return chunks, nil
}

// Close releases the vector database resources.
func (v *VectorDB) Close() error {
	return nil
}
