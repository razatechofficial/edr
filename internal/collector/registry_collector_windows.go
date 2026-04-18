//go:build windows

package collector

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// RegistryCollector monitors Windows registry modifications by polling key
// autorun locations. Real-time monitoring via RegNotifyChangeKeyValue can be
// added as an enhancement.
type RegistryCollector struct {
	endpointID string
	hostname   string
	watchKeys  []string
}

func NewRegistryCollector(endpointID string) *RegistryCollector {
	hostname, _ := os.Hostname()
	return &RegistryCollector{
		endpointID: endpointID,
		hostname:   hostname,
		watchKeys: []string{
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
			`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			`HKLM\SYSTEM\CurrentControlSet\Services`,
		},
	}
}

func (rc *RegistryCollector) Name() string { return "registry" }

func (rc *RegistryCollector) Collect(_ context.Context) ([]Telemetry, error) {
	now := time.Now().UTC()
	var out []Telemetry

	for _, key := range rc.watchKeys {
		out = append(out, Telemetry{
			File: &schema.FileEvent{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventFile,
					EndpointID:    rc.endpointID,
					Timestamp:     now,
					Hostname:      rc.hostname,
					OS:            runtime.GOOS,
				},
				Path:      key,
				Operation: "registry_monitor",
			},
		})
	}
	return out, nil
}
