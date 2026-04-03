package collector

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]schema.ProcessEvent, error)
}

type ProcessCollector struct {
	EndpointID string
	Hostname   string
}

func NewProcessCollector(endpointID string) (*ProcessCollector, error) {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return &ProcessCollector{EndpointID: endpointID, Hostname: host}, nil
}

func (c *ProcessCollector) Name() string { return "process" }

func (c *ProcessCollector) Collect(context.Context) ([]schema.ProcessEvent, error) {
	now := time.Now().UTC()
	evt := schema.ProcessEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventProcess,
			EndpointID:    c.EndpointID,
			Timestamp:     now,
			Hostname:      c.Hostname,
			OS:            runtime.GOOS,
		},
		PID:         os.Getpid(),
		PPID:        os.Getppid(),
		ParentName:  "",
		ProcessName: "edr-agent",
		ProcessPath: os.Args[0],
		CommandLine: "",
		User:        os.Getenv("USER"),
	}
	return []schema.ProcessEvent{evt}, nil
}
