package response

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// persistedRecord is what survives a restart.
//
// The rollback itself is a closure built at the moment the action ran, and a
// closure cannot be written to disk. What can be written is a command that
// undoes the action — `iptables -D …`, `netsh … delete rule …` — so that is
// recorded alongside, and a restart replays it rather than trying to resurrect
// the function.
type persistedRecord struct {
	ContainmentID string    `json:"containment_id"`
	HostID        string    `json:"host_id,omitempty"`
	Action        Action    `json:"action"`
	Target        string    `json:"target,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	Note          string    `json:"note,omitempty"`
	// RollbackArgv undoes the action. Empty means the containment can be
	// reported after a restart but not lifted automatically.
	RollbackArgv []string `json:"rollback_argv,omitempty"`
}

// Recoverable reports whether this record can be undone without the closure.
func (r persistedRecord) Recoverable() bool { return len(r.RollbackArgv) >= 1 }

// rollbackStore writes the active containments to a file.
//
// Without it, an agent restart loses every pending expiry: a host isolated for
// thirty minutes stays isolated indefinitely, because the timer that would have
// released it died with the process and nothing records that it ever existed.
// That is a worse failure than not isolating at all, since it is silent.
type rollbackStore struct {
	path   string
	logger *zap.Logger
}

func newRollbackStore(path string, logger *zap.Logger) *rollbackStore {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &rollbackStore{path: path, logger: logger}
}

// save writes the records atomically.
//
// Temp file plus rename: a crash during the write must not leave a truncated
// file, because the next start would then read it as "nothing is contained" and
// silently abandon whatever was.
func (s *rollbackStore) save(records []persistedRecord) error {
	if s == nil || s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("rollback store: create dir: %w", err)
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("rollback store: encode: %w", err)
	}
	tmp := s.path + ".tmp"
	// 0600: the records name isolated hosts, blocked addresses and quarantined
	// paths, which is a map of where the incident is.
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("rollback store: write: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("rollback store: commit: %w", err)
	}
	return nil
}

// load reads the records back. A missing file is not an error; a corrupt one is
// reported and treated as empty, because refusing to start would leave the
// endpoint with no agent at all.
func (s *rollbackStore) load() []persistedRecord {
	if s == nil || s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			s.logger.Error("rollback store unreadable; active containments cannot be recovered",
				zap.String("path", s.path), zap.Error(err))
		}
		return nil
	}
	var records []persistedRecord
	if err := json.Unmarshal(data, &records); err != nil {
		s.logger.Error("rollback store corrupt; active containments cannot be recovered",
			zap.String("path", s.path), zap.Error(err))
		return nil
	}
	return records
}

// argvRollback turns a recorded command into a rollback function.
func argvRollback(argv []string) func(context.Context) error {
	if len(argv) == 0 {
		return nil
	}
	return func(ctx context.Context) error {
		return exec.CommandContext(ctx, argv[0], argv[1:]...).Run()
	}
}
