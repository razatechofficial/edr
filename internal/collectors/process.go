package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// ProcessExecEvent is emitted when a process executes a new binary.
type ProcessExecEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	PID        uint32    `json:"pid"`
	TID        uint32    `json:"tid"`
	PPID       uint32    `json:"ppid"`
	UID        uint32    `json:"uid"`
	GID        uint32    `json:"gid"`
	User       string    `json:"user"`
	Group      string    `json:"group"`
	ExePath    string    `json:"exe_path"`
	Args       []string  `json:"args,omitempty"`
	Cwd        string    `json:"cwd"`
	SHA256     string    `json:"sha256,omitempty"`
	ParentComm string    `json:"parent_comm,omitempty"`
	IsElevated bool      `json:"is_elevated"`
}

// ProcessExitEvent is emitted when a process terminates.
type ProcessExitEvent struct {
	Timestamp time.Time     `json:"timestamp"`
	PID       uint32        `json:"pid"`
	TID       uint32        `json:"tid"`
	ExitCode  int32         `json:"exit_code"`
	Signal    int32         `json:"signal"`
	Duration  time.Duration `json:"duration_ns"`
}

// ProcessForkEvent is emitted when a process forks a child.
type ProcessForkEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	ParentPID  uint32    `json:"parent_pid"`
	ChildPID   uint32    `json:"child_pid"`
	CloneFlags uint64    `json:"clone_flags"`
}

type processInfo struct {
	pid       uint32
	ppid      uint32
	comm      string
	exePath   string
	startTime time.Time
	uid       uint32
	gid       uint32
}

// ProcessCollector handles process creation, execution, and exit events.
// It maintains an in-memory process tree for parent chain lookups and
// enriches events with file hashes, user resolution, and elevation status.
type ProcessCollector struct {
	logger *zap.Logger
	out    chan<- interface{}
	mu     sync.RWMutex
	tree   map[uint32]*processInfo
}

// NewProcessCollector creates a ProcessCollector with the given logger.
func NewProcessCollector(logger *zap.Logger) *ProcessCollector {
	return &ProcessCollector{
		logger: logger,
		tree:   make(map[uint32]*processInfo),
	}
}

// Name returns the collector identifier.
func (c *ProcessCollector) Name() string { return "process" }

// EventTypes returns the coarse event types this collector subscribes to.
func (c *ProcessCollector) EventTypes() []events.EventType {
	return []events.EventType{events.EventProcess}
}

// Start initializes the process collector and stores the output channel.
func (c *ProcessCollector) Start(_ context.Context, _ *kernel.RingBuffer, out chan<- interface{}) error {
	c.out = out
	return nil
}

// Stop is a no-op; the process collector has no background goroutines.
func (c *ProcessCollector) Stop() error { return nil }

func (c *ProcessCollector) processRaw(evt *RawEvent) {
	switch evt.Type {
	case EventProcessExec:
		c.handleExec(evt)
	case EventProcessExit:
		c.handleExit(evt)
	case EventProcessFork:
		c.handleFork(evt)
	}
}

func (c *ProcessCollector) handleExec(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	ppid := r.Uint32()
	exePath := r.String()
	argsRaw := r.String()
	cwd := r.String()
	comm := r.String()
	if r.Err() != nil {
		c.logger.Warn("malformed process exec payload", zap.Error(r.Err()))
		return
	}

	var args []string
	if argsRaw != "" {
		args = strings.Split(argsRaw, "\x00")
	}

	hash, err := hashFile(exePath)
	if err != nil {
		c.logger.Debug("failed to hash binary",
			zap.String("path", exePath), zap.Error(err))
	}

	parentComm := c.lookupComm(ppid)

	c.mu.Lock()
	c.tree[evt.PID] = &processInfo{
		pid:       evt.PID,
		ppid:      ppid,
		comm:      comm,
		exePath:   exePath,
		startTime: evt.Timestamp,
		uid:       evt.UID,
		gid:       evt.GID,
	}
	c.mu.Unlock()

	c.emit(&ProcessExecEvent{
		Timestamp:  evt.Timestamp,
		PID:        evt.PID,
		TID:        evt.TID,
		PPID:       ppid,
		UID:        evt.UID,
		GID:        evt.GID,
		User:       resolveUser(evt.UID),
		Group:      resolveGroup(evt.GID),
		ExePath:    exePath,
		Args:       args,
		Cwd:        cwd,
		SHA256:     hash,
		ParentComm: parentComm,
		IsElevated: evt.UID == 0,
	})
}

func (c *ProcessCollector) handleExit(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	exitCode := r.Int32()
	signal := r.Int32()
	startNs := r.Uint64()
	if r.Err() != nil {
		c.logger.Warn("malformed process exit payload", zap.Error(r.Err()))
		return
	}

	startTime := time.Unix(0, int64(startNs))
	duration := evt.Timestamp.Sub(startTime)

	c.mu.Lock()
	delete(c.tree, evt.PID)
	c.mu.Unlock()

	c.emit(&ProcessExitEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		TID:       evt.TID,
		ExitCode:  exitCode,
		Signal:    signal,
		Duration:  duration,
	})
}

func (c *ProcessCollector) handleFork(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	childPID := r.Uint32()
	cloneFlags := r.Uint64()
	if r.Err() != nil {
		c.logger.Warn("malformed process fork payload", zap.Error(r.Err()))
		return
	}

	c.mu.Lock()
	if parent, ok := c.tree[evt.PID]; ok {
		c.tree[childPID] = &processInfo{
			pid:       childPID,
			ppid:      evt.PID,
			comm:      parent.comm,
			exePath:   parent.exePath,
			startTime: evt.Timestamp,
			uid:       evt.UID,
			gid:       evt.GID,
		}
	}
	c.mu.Unlock()

	c.emit(&ProcessForkEvent{
		Timestamp:  evt.Timestamp,
		ParentPID:  evt.PID,
		ChildPID:   childPID,
		CloneFlags: cloneFlags,
	})
}

func (c *ProcessCollector) lookupComm(pid uint32) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if info, ok := c.tree[pid]; ok {
		return info.comm
	}
	return ""
}

func (c *ProcessCollector) emit(evt interface{}) {
	select {
	case c.out <- evt:
	default:
		c.logger.Warn("output channel full, dropping process event")
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > maxHashFileSize {
		return "", fmt.Errorf("file exceeds %d byte hash limit", maxHashFileSize)
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func resolveUser(uid uint32) string {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return strconv.FormatUint(uint64(uid), 10)
	}
	return u.Username
}

func resolveGroup(gid uint32) string {
	g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		return strconv.FormatUint(uint64(gid), 10)
	}
	return g.Name
}
