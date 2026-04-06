package collectors

import (
	"context"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

const (
	protRead  = 0x1
	protWrite = 0x2
	protExec  = 0x4
	protRWX   = protRead | protWrite | protExec
)

// MemoryAllocEvent is emitted when virtual memory is allocated.
type MemoryAllocEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	PID        uint32    `json:"pid"`
	TargetPID  uint32    `json:"target_pid"`
	Address    uint64    `json:"address"`
	Size       uint64    `json:"size"`
	Protection uint32    `json:"protection"`
	IsRemote   bool      `json:"is_remote"`
}

// MemoryWriteEvent is emitted on cross-process memory writes.
type MemoryWriteEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	TargetPID uint32    `json:"target_pid"`
	Address   uint64    `json:"address"`
	Size      uint64    `json:"size"`
	IsRemote  bool      `json:"is_remote"`
}

// MemoryProtectEvent is emitted when memory page protections are changed.
// IsRWX is flagged when the new protection grants read+write+execute,
// which is a strong indicator of code injection.
type MemoryProtectEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	PID           uint32    `json:"pid"`
	TargetPID     uint32    `json:"target_pid"`
	Address       uint64    `json:"address"`
	Size          uint64    `json:"size"`
	OldProtection uint32    `json:"old_protection"`
	NewProtection uint32    `json:"new_protection"`
	IsRWX         bool      `json:"is_rwx"`
	IsRemote      bool      `json:"is_remote"`
}

// MemoryCollector handles virtual memory operation events, detecting
// cross-process operations and RWX page allocations.
type MemoryCollector struct {
	logger *zap.Logger
	out    chan<- interface{}
}

// NewMemoryCollector creates a MemoryCollector with the given logger.
func NewMemoryCollector(logger *zap.Logger) *MemoryCollector {
	return &MemoryCollector{logger: logger}
}

// Name returns the collector identifier.
func (c *MemoryCollector) Name() string { return "memory" }

// EventTypes returns the coarse event types this collector subscribes to.
func (c *MemoryCollector) EventTypes() []events.EventType {
	return []events.EventType{events.EventMemory}
}

// Start stores the output channel.
func (c *MemoryCollector) Start(_ context.Context, _ *kernel.RingBuffer, out chan<- interface{}) error {
	c.out = out
	return nil
}

// Stop is a no-op.
func (c *MemoryCollector) Stop() error { return nil }

func (c *MemoryCollector) processRaw(evt *RawEvent) {
	switch evt.Type {
	case EventMemoryAlloc:
		c.handleAlloc(evt)
	case EventMemoryWrite:
		c.handleWrite(evt)
	case EventMemoryProtect:
		c.handleProtect(evt)
	}
}

func (c *MemoryCollector) handleAlloc(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	targetPID := r.Uint32()
	addr := r.Uint64()
	size := r.Uint64()
	prot := r.Uint32()
	if r.Err() != nil {
		c.logger.Warn("malformed memory alloc payload", zap.Error(r.Err()))
		return
	}

	c.emit(&MemoryAllocEvent{
		Timestamp:  evt.Timestamp,
		PID:        evt.PID,
		TargetPID:  targetPID,
		Address:    addr,
		Size:       size,
		Protection: prot,
		IsRemote:   targetPID != evt.PID,
	})
}

func (c *MemoryCollector) handleWrite(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	targetPID := r.Uint32()
	addr := r.Uint64()
	size := r.Uint64()
	if r.Err() != nil {
		c.logger.Warn("malformed memory write payload", zap.Error(r.Err()))
		return
	}

	c.emit(&MemoryWriteEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		TargetPID: targetPID,
		Address:   addr,
		Size:      size,
		IsRemote:  targetPID != evt.PID,
	})
}

func (c *MemoryCollector) handleProtect(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	targetPID := r.Uint32()
	addr := r.Uint64()
	size := r.Uint64()
	oldProt := r.Uint32()
	newProt := r.Uint32()
	if r.Err() != nil {
		c.logger.Warn("malformed memory protect payload", zap.Error(r.Err()))
		return
	}

	c.emit(&MemoryProtectEvent{
		Timestamp:     evt.Timestamp,
		PID:           evt.PID,
		TargetPID:     targetPID,
		Address:       addr,
		Size:          size,
		OldProtection: oldProt,
		NewProtection: newProt,
		IsRWX:         newProt&protRWX == protRWX,
		IsRemote:      targetPID != evt.PID,
	})
}

func (c *MemoryCollector) emit(evt interface{}) {
	select {
	case c.out <- evt:
	default:
		c.logger.Warn("output channel full, dropping memory event")
	}
}
