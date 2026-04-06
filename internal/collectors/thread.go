package collectors

import (
	"context"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// ThreadCreateEvent is emitted when a new thread is created.
// IsRemote is true when the creator's PID differs from the target,
// which is a common indicator of process injection.
type ThreadCreateEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	PID        uint32    `json:"pid"`
	TID        uint32    `json:"tid"`
	TargetPID  uint32    `json:"target_pid"`
	TargetTID  uint32    `json:"target_tid"`
	EntryPoint uint64    `json:"entry_point"`
	IsRemote   bool      `json:"is_remote"`
}

// ThreadExitEvent is emitted when a thread terminates.
type ThreadExitEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	TID       uint32    `json:"tid"`
	ExitCode  int32     `json:"exit_code"`
}

// ThreadCollector handles thread creation and termination events,
// with special attention to remote thread injection detection.
type ThreadCollector struct {
	logger *zap.Logger
	out    chan<- interface{}
}

// NewThreadCollector creates a ThreadCollector with the given logger.
func NewThreadCollector(logger *zap.Logger) *ThreadCollector {
	return &ThreadCollector{logger: logger}
}

// Name returns the collector identifier.
func (c *ThreadCollector) Name() string { return "thread" }

// EventTypes returns the coarse event types this collector subscribes to.
func (c *ThreadCollector) EventTypes() []events.EventType {
	return []events.EventType{events.EventProcess}
}

// Start stores the output channel.
func (c *ThreadCollector) Start(_ context.Context, _ *kernel.RingBuffer, out chan<- interface{}) error {
	c.out = out
	return nil
}

// Stop is a no-op.
func (c *ThreadCollector) Stop() error { return nil }

func (c *ThreadCollector) processRaw(evt *RawEvent) {
	switch evt.Type {
	case EventThreadCreate:
		c.handleCreate(evt)
	case EventThreadExit:
		c.handleExit(evt)
	}
}

func (c *ThreadCollector) handleCreate(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	targetPID := r.Uint32()
	targetTID := r.Uint32()
	entryPoint := r.Uint64()
	if r.Err() != nil {
		c.logger.Warn("malformed thread create payload", zap.Error(r.Err()))
		return
	}

	c.emit(&ThreadCreateEvent{
		Timestamp:  evt.Timestamp,
		PID:        evt.PID,
		TID:        evt.TID,
		TargetPID:  targetPID,
		TargetTID:  targetTID,
		EntryPoint: entryPoint,
		IsRemote:   targetPID != evt.PID,
	})
}

func (c *ThreadCollector) handleExit(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	exitCode := r.Int32()
	if r.Err() != nil {
		c.logger.Warn("malformed thread exit payload", zap.Error(r.Err()))
		return
	}

	c.emit(&ThreadExitEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		TID:       evt.TID,
		ExitCode:  exitCode,
	})
}

func (c *ThreadCollector) emit(evt interface{}) {
	select {
	case c.out <- evt:
	default:
		c.logger.Warn("output channel full, dropping thread event")
	}
}
