//go:build darwin && !cgo

package kernel

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/pkg/events"
)

// ESFDriver is the macOS Endpoint Security Framework driver. This build
// is a no-op stub used when cgo is disabled; the full implementation
// lives in driver_darwin.go (requires cgo for the ESF C bridge).
type ESFDriver struct {
	agentID string
	policy  EventPolicy
	stats   DriverStats
	running atomic.Bool
}

// NewESFDriver creates a new ESF driver instance.
func NewESFDriver(agentID string) (*ESFDriver, error) {
	return &ESFDriver{
		agentID: agentID,
		policy:  DefaultPolicy(),
	}, nil
}

func (d *ESFDriver) Start(ctx context.Context, buf *RingBuffer) error {
	if d.running.Load() {
		return fmt.Errorf("esf: already running")
	}
	d.running.Store(true)
	d.stats.LastEventTime = time.Now()
	return fmt.Errorf("esf: cgo required for Endpoint Security Framework, build with CGO_ENABLED=1")
}

func (d *ESFDriver) Stop() error {
	d.running.Store(false)
	return nil
}

func (d *ESFDriver) SetPolicy(policy EventPolicy) error {
	d.policy = policy
	return nil
}

func (d *ESFDriver) Name() string { return "esf" }

func (d *ESFDriver) Capabilities() []events.EventType {
	return []events.EventType{
		events.EventProcess,
		events.EventFile,
		events.EventNetwork,
		events.EventModule,
		events.EventMount,
		events.EventSignal,
	}
}
