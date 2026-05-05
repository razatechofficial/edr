//go:build !windows && !linux && !darwin

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

func NewRegistryCollector(endpointID string) *RegistryCollector {
	return &RegistryCollector{
		endpointID: endpointID,
		hostname:   "unknown",
		keys:       defaultRegistryEquivalentPaths(),
		prev:       map[string]string{},
	}
}

type RegistryCollector struct {
	endpointID string
	hostname   string
	keys       []string
	prev       map[string]string
	mu         sync.Mutex

	scans   atomic.Uint64
	emitted atomic.Uint64
}

func (rc *RegistryCollector) Name() string                                  { return "registry" }
func (rc *RegistryCollector) Collect(_ context.Context) ([]Telemetry, error) {
	rc.scans.Add(1)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var out []Telemetry
	now := time.Now().UTC()
	for _, p := range rc.keys {
		b, err := readRareRegistryEquivalentValue(p)
		if err != nil {
			continue
		}
		cur := strings.TrimSpace(b)
		old, had := rc.prev[p]
		if had && old == cur {
			continue
		}
		rc.prev[p] = cur
		if !had {
			continue
		}
		out = append(out, Telemetry{
			Registry: &schema.RegistryEvent{
				BaseEvent: schema.BaseEvent{
					SchemaVersion: schema.SchemaVersionV1,
					EventType:     schema.EventRegistry,
					EndpointID:    rc.endpointID,
					Timestamp:     now,
					Hostname:      rc.hostname,
					OS:            runtime.GOOS,
				},
				KeyPath:   p,
				ValueName: "content",
				Operation: "set",
				OldData:   old,
				NewData:   cur,
			},
		})
		rc.emitted.Add(1)
	}
	return out, nil
}

func (rc *RegistryCollector) ExportMonitoringHealth() map[string]any {
	return MonitoringSource{
		Name:   "registry",
		OS:     runtime.GOOS,
		Source: "rare_registry_probe",
		Status: "healthy",
		EPSIn:  rc.scans.Load(),
		EPSOut: rc.emitted.Load(),
		Notes:  strings.Join(rc.keys, ";"),
	}.ToMap()
}

func defaultRegistryEquivalentPaths() []string {
	return []string{
		"runtime.goos",
		"runtime.goarch",
		"os.hostname",
		"file:/etc/os-release",
		"file:/etc/rc.conf",
	}
}

func readRareRegistryEquivalentValue(key string) (string, error) {
	switch key {
	case "runtime.goos":
		return runtime.GOOS, nil
	case "runtime.goarch":
		return runtime.GOARCH, nil
	case "os.hostname":
		h, err := os.Hostname()
		if err != nil {
			return "", err
		}
		return h, nil
	}
	const prefix = "file:"
	if strings.HasPrefix(key, prefix) {
		path := strings.TrimSpace(strings.TrimPrefix(key, prefix))
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", os.ErrNotExist
}
