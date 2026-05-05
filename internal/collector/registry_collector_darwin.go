//go:build darwin

package collector

import (
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

type RegistryCollector struct {
	endpointID string
	hostname   string
	keys       []string
	prev       map[string]string
	mu         sync.Mutex

	scans   atomic.Uint64
	emitted atomic.Uint64
}

func NewRegistryCollector(endpointID string) *RegistryCollector {
	host, _ := os.Hostname()
	return &RegistryCollector{
		endpointID: endpointID,
		hostname:   host,
		keys: []string{
			"/Library/Preferences/com.apple.loginwindow.plist",
			"/Library/Preferences/com.apple.alf.plist",
			"/Library/Preferences/com.apple.security.plist",
		},
		prev: map[string]string{},
	}
}

func (rc *RegistryCollector) Name() string { return "registry" }

func (rc *RegistryCollector) Collect(_ context.Context) ([]Telemetry, error) {
	rc.scans.Add(1)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var out []Telemetry
	now := time.Now().UTC()
	for _, p := range rc.keys {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		cur := strings.TrimSpace(string(b))
		old, had := rc.prev[p]
		if had && old == cur {
			continue
		}
		rc.prev[p] = cur
		if !had {
			continue
		}
		out = append(out, Telemetry{Registry: &schema.RegistryEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventRegistry,
				EndpointID:    rc.endpointID,
				Timestamp:     now,
				Hostname:      rc.hostname,
				OS:            runtime.GOOS,
			},
			KeyPath:   p,
			ValueName: "plist",
			Operation: "set",
			OldData:   old,
			NewData:   cur,
		}})
		rc.emitted.Add(1)
	}
	return out, nil
}

func (rc *RegistryCollector) ExportMonitoringHealth() map[string]any {
	return MonitoringSource{
		Name:   "registry",
		OS:     runtime.GOOS,
		Source: "darwin_plist_registry",
		Status: "healthy",
		EPSIn:  rc.scans.Load(),
		EPSOut: rc.emitted.Load(),
		Notes:  strings.Join(rc.keys, ";"),
	}.ToMap()
}

