package collector

import (
	"context"

	"github.com/razatechofficial/edr/internal/schema"
)

// Telemetry is one unit of host telemetry (at most one payload pointer is set).
type Telemetry struct {
	Process *schema.ProcessEvent
	Network *schema.NetworkEvent
	Auth    *schema.AuthEvent
	File    *schema.FileEvent
}

// Collector gathers host telemetry for the detection engine.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Telemetry, error)
}
