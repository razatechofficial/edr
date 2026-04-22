package response

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RollbackManager tracks reversible response actions and optional auto-expiry.
type RollbackManager struct {
	records map[string]*RollbackRecord
	mu      sync.Mutex
}

// RollbackRecord is a single registered rollback.
type RollbackRecord struct {
	ContainmentID string
	Action        Action
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RollbackFn    func(ctx context.Context) error
	Reversible    bool
	Note          string
}

// NewRollbackManager creates an empty manager.
func NewRollbackManager() *RollbackManager {
	return &RollbackManager{records: make(map[string]*RollbackRecord)}
}

// Register stores a rollback function for a containment.
func (m *RollbackManager) Register(c Containment, rollbackFn func(ctx context.Context) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[c.ID] = &RollbackRecord{
		ContainmentID: c.ID,
		Action:        c.Action,
		CreatedAt:     time.Now(),
		ExpiresAt:     c.ExpiresAt,
		RollbackFn:    rollbackFn,
		Reversible:    rollbackFn != nil,
	}
}

// Rollback runs the stored function for the given id.
func (m *RollbackManager) Rollback(ctx context.Context, id string) error {
	m.mu.Lock()
	rec, ok := m.records[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("no rollback record for %s", id)
	}
	if !rec.Reversible {
		if rec.Note != "" {
			return fmt.Errorf("action not reversible: %s", rec.Note)
		}
		return fmt.Errorf("action not reversible")
	}
	return rec.RollbackFn(ctx)
}

// Delete removes a record (e.g. after successful manual rollback).
func (m *RollbackManager) Delete(id string) {
	m.mu.Lock()
	delete(m.records, id)
	m.mu.Unlock()
}

// AutoRollbackLoop calls rollback for expired records periodically.
func (m *RollbackManager) AutoRollbackLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.runExpired(ctx)
		}
	}
}

// RunExpiredOnce runs one expiry scan (exposed for unit tests).
func (m *RollbackManager) RunExpiredOnce(ctx context.Context) {
	m.runExpired(ctx)
}

func (m *RollbackManager) runExpired(ctx context.Context) {
	now := time.Now()
	type exp struct {
		id string
		fn func(context.Context) error
	}
	m.mu.Lock()
	var batch []exp
	for id, rec := range m.records {
		if rec.ExpiresAt.IsZero() {
			continue
		}
		if now.After(rec.ExpiresAt) && rec.Reversible && rec.RollbackFn != nil {
			batch = append(batch, exp{id: id, fn: rec.RollbackFn})
		}
	}
	for _, e := range batch {
		delete(m.records, e.id)
	}
	m.mu.Unlock()
	for _, e := range batch {
		_ = e.fn(ctx)
	}
}
