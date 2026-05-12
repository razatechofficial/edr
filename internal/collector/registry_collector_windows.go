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
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"golang.org/x/sys/windows/registry"
)

// RegistryCollector snapshots watched keys and emits RegistryEvent rows when
// values are added, changed, or removed compared to the previous Collect pass.
//
// On hosts where the Microsoft-Windows-Kernel-Registry ETW provider is
// delivering events through the kernel driver, this collector becomes a cold
// fallback (SetETWActive(true)) and skips its poll cycle to avoid duplicate
// emissions. The health snapshot still records its observed state.
type RegistryCollector struct {
	mu          sync.Mutex
	endpointID  string
	hostname    string
	watchKeys   []string
	prev        map[string]map[string]string
	initialized map[string]bool

	etwActive atomic.Bool
	scans     atomic.Uint64
	emitted   atomic.Uint64
	skipped   atomic.Uint64

	notifyOnce    sync.Once
	notifyRunning atomic.Bool
	notifyPending atomic.Bool
	notifyWakeups atomic.Uint64
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
			`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
			`HKLM\SYSTEM\CurrentControlSet\Services`,
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			`HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`,
			// P0-9 — persistence locations missing from the original list.
			// COM object hijack (CLSID InProcServer32/LocalServer32).
			`HKLM\SOFTWARE\Classes\CLSID`,
			`HKCU\SOFTWARE\Classes\CLSID`,
			// Credential providers and Lsa packages (LSA notification packages,
			// authentication packages, security packages, etc).
			`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`,
			// AppCertDlls — loaded into every process that calls CreateProcess.
			`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`,
			// Shim database persistence.
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB`,
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom`,
			// UserInitMprLogonScript (logon script persistence).
			`HKCU\Environment`,
			// Policies-Run / Policies-Explorer\Run.
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
			`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
			// Terminal Server install hive (sysWOW64-style 32-bit nested Run).
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`,
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
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

// SetETWActive lets the agent declare that the Kernel-Registry ETW provider
// is delivering events; the polling collector then becomes a no-op until the
// flag is cleared. Safe to call from any goroutine.
func (rc *RegistryCollector) SetETWActive(active bool) {
	rc.etwActive.Store(active)
}

// ExportMonitoringHealth surfaces fallback status to the doctor command.
func (rc *RegistryCollector) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:    "registry",
		OS:      "windows",
		Source:  "registry_polling",
		Status:  "healthy",
		EPSIn:   rc.scans.Load(),
		EPSOut:  rc.emitted.Load(),
		Dropped: rc.skipped.Load(),
	}
	if rc.etwActive.Load() {
		src.Status = "standby"
		src.Notes = "ETW Kernel-Registry is primary; polling disabled"
	} else {
		if rc.notifyRunning.Load() {
			if src.Notes != "" {
				src.Notes += "; "
			}
			src.Notes += "reg_notify=on"
		}
	}
	m := src.ToMap()
	m["reg_notify_wakeups"] = float64(rc.notifyWakeups.Load())
	m["reg_notify_pending"] = rc.notifyPending.Load()
	return m
}

func (rc *RegistryCollector) Collect(_ context.Context) ([]Telemetry, error) {
	now := time.Now().UTC()
	if rc.etwActive.Load() {
		rc.skipped.Add(1)
		return nil, nil
	}
	rc.notifyOnce.Do(func() {
		rc.StartRegistryNotifyLoop(context.Background())
	})
	_ = rc.notifyPending.Swap(false)
	rc.scans.Add(1)
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
				rc.emitted.Add(1)
			}
		}
		for vn := range prev {
			if _, ok := cur[vn]; !ok {
				out = append(out, Telemetry{
					Registry: rc.newEvent(keyPath, vn, "delete", prev[vn], "", now),
				})
				rc.emitted.Add(1)
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
