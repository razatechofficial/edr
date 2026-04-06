//go:build windows

package collectors

import (
	"context"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// RegistryEvent is emitted when a Windows registry key or value is modified.
type RegistryEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	Operation string    `json:"operation"`
	KeyPath   string    `json:"key_path"`
	ValueName string    `json:"value_name,omitempty"`
	ValueType uint32    `json:"value_type,omitempty"`
	ValueData []byte    `json:"value_data,omitempty"`
}

// RegistryCollector handles Windows registry modification events.
type RegistryCollector struct {
	logger *zap.Logger
	out    chan<- interface{}
}

// NewRegistryCollector creates a RegistryCollector with the given logger.
func NewRegistryCollector(logger *zap.Logger) *RegistryCollector {
	return &RegistryCollector{logger: logger}
}

// Name returns the collector identifier.
func (c *RegistryCollector) Name() string { return "registry" }

// EventTypes returns the coarse event types this collector subscribes to.
func (c *RegistryCollector) EventTypes() []events.EventType {
	return []events.EventType{events.EventRegistry}
}

// Start stores the output channel.
func (c *RegistryCollector) Start(_ context.Context, _ *kernel.RingBuffer, out chan<- interface{}) error {
	c.out = out
	return nil
}

// Stop is a no-op.
func (c *RegistryCollector) Stop() error { return nil }

func (c *RegistryCollector) processRaw(evt *RawEvent) {
	switch evt.Type {
	case EventRegistryCreate, EventRegistrySet, EventRegistryDelete:
	default:
		return
	}

	r := newPayloadReader(evt.Payload)
	op := r.Uint8()
	keyPath := r.String()
	valueName := r.String()
	valueType := r.Uint32()
	dataLen := r.Uint16()
	valueData := r.Bytes(int(dataLen))
	if r.Err() != nil {
		c.logger.Warn("malformed registry payload", zap.Error(r.Err()))
		return
	}

	var opName string
	switch op {
	case 0:
		opName = "create"
	case 1:
		opName = "set"
	case 2:
		opName = "delete"
	default:
		opName = "unknown"
	}

	c.emit(&RegistryEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		Operation: opName,
		KeyPath:   keyPath,
		ValueName: valueName,
		ValueType: valueType,
		ValueData: valueData,
	})
}

func (c *RegistryCollector) emit(evt interface{}) {
	select {
	case c.out <- evt:
	default:
		c.logger.Warn("output channel full, dropping registry event")
	}
}
