//go:build !windows

package collectors

import (
	"context"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// RegistryEvent is a placeholder on non-Windows platforms for API compatibility.
type RegistryEvent struct{}

// RegistryCollector is a no-op on non-Windows platforms.
type RegistryCollector struct {
	logger *zap.Logger
}

// NewRegistryCollector returns a no-op RegistryCollector on non-Windows platforms.
func NewRegistryCollector(logger *zap.Logger) *RegistryCollector {
	return &RegistryCollector{logger: logger}
}

// Name returns the collector identifier.
func (c *RegistryCollector) Name() string { return "registry" }

// EventTypes returns nil; no registry events are produced on non-Windows.
func (c *RegistryCollector) EventTypes() []events.EventType { return nil }

// Start is a no-op.
func (c *RegistryCollector) Start(_ context.Context, _ *kernel.RingBuffer, _ chan<- interface{}) error {
	return nil
}

// Stop is a no-op.
func (c *RegistryCollector) Stop() error { return nil }

func (c *RegistryCollector) processRaw(_ *RawEvent) {}
