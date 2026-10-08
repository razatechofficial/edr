package response

import (
	"context"
	"fmt"
	"go.uber.org/zap"
	"sync"
	"time"
)

// RollbackManager tracks reversible response actions and optional auto-expiry.
type RollbackManager struct {
	records map[string]*RollbackRecord
	mu      sync.Mutex
	// store persists the records so a restart does not orphan them. Nil keeps
	// the in-memory behaviour, which is what the tests and older callers use.
	store  *rollbackStore
	logger *zap.Logger
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
	// HostID and Target describe what is contained, so a recovered record can
	// be reported to an operator rather than being an opaque identifier.
	HostID string
	Target string
	// RollbackArgv is the command that undoes the action. It is what survives a
	// restart; RollbackFn does not.
	RollbackArgv []string
}

// NewRollbackManager creates an empty in-memory manager.
func NewRollbackManager() *RollbackManager {
	return &RollbackManager{records: make(map[string]*RollbackRecord)}
}

// NewPersistentRollbackManager creates a manager that survives a restart.
//
// Records written previously are loaded immediately. Those carrying a rollback
// command are restored as live records and will expire normally; those without
// are reported, because a containment nobody can lift still has to be visible
// to whoever has to lift it by hand.
func NewPersistentRollbackManager(path string, logger *zap.Logger) *RollbackManager {
	if logger == nil {
		logger = zap.NewNop()
	}
	m := &RollbackManager{
		records: make(map[string]*RollbackRecord),
		store:   newRollbackStore(path, logger),
		logger:  logger,
	}
	var orphaned int
	for _, pr := range m.store.load() {
		rec := &RollbackRecord{
			ContainmentID: pr.ContainmentID,
			Action:        pr.Action,
			CreatedAt:     pr.CreatedAt,
			ExpiresAt:     pr.ExpiresAt,
			Note:          pr.Note,
			HostID:        pr.HostID,
			Target:        pr.Target,
			RollbackArgv:  pr.RollbackArgv,
		}
		if pr.Recoverable() {
			rec.RollbackFn = argvRollback(pr.RollbackArgv)
			rec.Reversible = true
		} else {
			orphaned++
			logger.Warn("containment recovered but cannot be lifted automatically",
				zap.String("containment_id", pr.ContainmentID),
				zap.Int("action", int(pr.Action)),
				zap.String("target", pr.Target),
				zap.Time("expires_at", pr.ExpiresAt),
			)
		}
		m.records[pr.ContainmentID] = rec
	}
	if n := len(m.records); n > 0 {
		logger.Info("active containments recovered",
			zap.Int("total", n),
			zap.Int("needing_manual_release", orphaned),
		)
	}
	return m
}

// Active returns the containments currently tracked, for reporting.
func (m *RollbackManager) Active() []RollbackRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RollbackRecord, 0, len(m.records))
	for _, rec := range m.records {
		out = append(out, *rec)
	}
	return out
}

// persistLocked writes the current records. The caller holds the mutex.
func (m *RollbackManager) persistLocked() {
	if m.store == nil {
		return
	}
	records := make([]persistedRecord, 0, len(m.records))
	for _, rec := range m.records {
		records = append(records, persistedRecord{
			ContainmentID: rec.ContainmentID,
			HostID:        rec.HostID,
			Action:        rec.Action,
			Target:        rec.Target,
			CreatedAt:     rec.CreatedAt,
			ExpiresAt:     rec.ExpiresAt,
			Note:          rec.Note,
			RollbackArgv:  rec.RollbackArgv,
		})
	}
	if err := m.store.save(records); err != nil && m.logger != nil {
		m.logger.Error("could not persist containment state", zap.Error(err))
	}
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
		HostID:        c.HostID,
		Target:        c.Target,
		RollbackArgv:  c.RollbackArgv,
	}
	m.persistLocked()
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
	m.persistLocked()
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
	if len(batch) > 0 {
		m.persistLocked()
	}
	m.mu.Unlock()
	for _, e := range batch {
		_ = e.fn(ctx)
	}
}
