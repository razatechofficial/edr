package testutil

import (
	"context"
	"encoding/json"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
)

// MockDriver is a kernel driver that emits pre-configured events for testing.
type MockDriver struct {
	events  [][]byte
	policy  kernel.EventPolicy
	started bool
	stopped bool
}

func NewMockDriver(rawEvents ...interface{}) *MockDriver {
	d := &MockDriver{}
	for _, e := range rawEvents {
		data, err := json.Marshal(e)
		if err != nil {
			panic("mock_driver: marshal event: " + err.Error())
		}
		d.events = append(d.events, data)
	}
	return d
}

func (d *MockDriver) Start(_ context.Context, buf *kernel.RingBuffer) error {
	d.started = true
	for _, data := range d.events {
		if err := buf.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func (d *MockDriver) Stop() error {
	d.stopped = true
	return nil
}

func (d *MockDriver) SetPolicy(policy kernel.EventPolicy) error {
	d.policy = policy
	return nil
}

func (d *MockDriver) Name() string { return "mock" }

func (d *MockDriver) Capabilities() []events.EventType {
	return []events.EventType{
		events.EventProcess,
		events.EventFile,
		events.EventNetwork,
	}
}

func (d *MockDriver) Started() bool { return d.started }
func (d *MockDriver) Stopped() bool { return d.stopped }
