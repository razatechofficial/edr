//go:build windows

package collector

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows/registry"
)

// RegistryCollector snapshots watched keys and emits RegistryEvent rows when
// values are added, changed, or removed compared to the previous Collect pass.
type RegistryCollector struct {
	mu         sync.Mutex
	endpointID string
	hostname   string
	watchKeys  []string
	prev       map[string]map[string]string
	initialized map[string]bool
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
		prev:        make(map[string]map[string]string),
		initialized: make(map[string]bool),
	}
}

func (rc *RegistryCollector) Name() string { return "registry" }

func parseRegistryRoot(full string) (registry.Key, string, bool) {
	rootName, subkey, ok := strings.Cut(full, `\`)
	if !ok || subkey == "" {
		return 0, "", false
	}
	switch strings.ToUpper(rootName) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, subkey, true
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, subkey, true
	default:
		return 0, "", false
	}
}

func readValueString(k registry.Key, name string) string {
	if s, _, err := k.GetStringValue(name); err == nil {
		return s
	}
	if n, _, err := k.GetIntegerValue(name); err == nil {
		return fmt.Sprintf("%d", n)
	}
	if b, _, err := k.GetBinaryValue(name); err == nil && len(b) > 0 {
		return hex.EncodeToString(b)
	}
	if ss, _, err := k.GetStringsValue(name); err == nil && len(ss) > 0 {
		return strings.Join(ss, "|")
	}
	return ""
}

func readKeySnapshot(k registry.Key) (map[string]string, error) {
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		out[name] = readValueString(k, name)
	}
	return out, nil
}

func (rc *RegistryCollector) Collect(_ context.Context) ([]Telemetry, error) {
	now := time.Now().UTC()
	rc.mu.Lock()
	defer rc.mu.Unlock()

	var out []Telemetry
	for _, keyPath := range rc.watchKeys {
		root, sub, ok := parseRegistryRoot(keyPath)
		if !ok {
			continue
		}
		k, err := registry.OpenKey(root, sub, registry.READ)
		if err != nil {
			continue
		}
		cur, err := readKeySnapshot(k)
		_ = k.Close()
		if err != nil {
			continue
		}

		prev := rc.prev[keyPath]
		if prev == nil {
			prev = make(map[string]string)
		}

		if !rc.initialized[keyPath] {
			rc.prev[keyPath] = cur
			rc.initialized[keyPath] = true
			continue
		}

		for vn, val := range cur {
			old, had := prev[vn]
			if !had || old != val {
				out = append(out, Telemetry{
					Registry: rc.newEvent(keyPath, vn, "set", old, val, now),
				})
			}
		}
		for vn := range prev {
			if _, ok := cur[vn]; !ok {
				out = append(out, Telemetry{
					Registry: rc.newEvent(keyPath, vn, "delete", prev[vn], "", now),
				})
			}
		}
		rc.prev[keyPath] = cur
	}
	return out, nil
}

func (rc *RegistryCollector) newEvent(keyPath, valueName, op, old, neu string, ts time.Time) *schema.RegistryEvent {
	return &schema.RegistryEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventRegistry,
			EndpointID:    rc.endpointID,
			Timestamp:     ts,
			Hostname:      rc.hostname,
			OS:            runtime.GOOS,
		},
		KeyPath:   keyPath,
		ValueName: valueName,
		Operation: op,
		OldData:   old,
		NewData:   neu,
	}
}
