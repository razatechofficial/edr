//go:build windows && integration

package kernel

// TEMPORARY DIAGNOSTIC — delete once the Windows capability-tracking defect is
// understood. It asserts nothing. Its only job is to print the real
// distribution of (provider GUID, event id, opcode) that a hosted
// windows-latest runner delivers, because windowsCapabilityForETWEvent's
// event-id tables were written from documentation and have never been checked
// against a live provider set.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type diagKey struct {
	Provider string
	EventID  uint16
	Opcode   uint8
	Version  uint8
}

func TestWindowsETWEventShapeDiagnostic(t *testing.T) {
	drv, err := NewETWDriver("etw-shape-diagnostic")
	if err != nil {
		t.Skipf("MISSING PREREQUISITE: ETW driver could not be constructed: %v", err)
	}
	buf := NewRingBuffer(8 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	if err := drv.Start(ctx, buf); err != nil {
		cancel()
		buf.Close()
		t.Skipf("MISSING PREREQUISITE: ETW session could not be started: %v", err)
	}
	t.Cleanup(func() {
		_ = drv.Stop()
		cancel()
		buf.Close()
	})

	for _, h := range drv.ProviderHealthSnapshot() {
		t.Logf("provider %-18s active=%v err=%s", h.Name, h.Active, h.Error)
	}

	// Generate activity in a child process while draining.
	done := make(chan struct{})
	go func() {
		defer close(done)
		self, _ := os.Executable()
		path := filepath.Join(t.TempDir(), "diag.txt")
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		if ln != nil {
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					_ = c.Close()
				}
			}()
		}
		for i := 0; i < 5; i++ {
			cmd := exec.Command(self)
			cmd.Env = append(os.Environ(), winHelperEnvVar+"=exec")
			_ = cmd.Run()

			cmd = exec.Command(self)
			cmd.Env = append(os.Environ(), winHelperEnvVar+"=write", winHelperArgVar+"="+path)
			_ = cmd.Run()

			if ln != nil {
				cmd = exec.Command(self)
				cmd.Env = append(os.Environ(), winHelperEnvVar+"=dial", winHelperArgVar+"="+ln.Addr().String())
				_ = cmd.Run()
			}
			_, _ = net.LookupHost("example.com")
			time.Sleep(500 * time.Millisecond)
		}
		if ln != nil {
			_ = ln.Close()
		}
	}()

	counts := map[diagKey]int{}
	samples := map[diagKey]string{}
	selfName := ""
	if self, err := os.Executable(); err == nil {
		selfName = strings.ToLower(filepath.Base(self))
	}
	var nameHits []string

	deadline := time.Now().Add(25 * time.Second)
	total := 0
	for time.Now().Before(deadline) {
		data, err := buf.TryRead()
		if err != nil || data == nil {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		var env map[string]interface{}
		if json.Unmarshal(data, &env) != nil {
			continue
		}
		total++
		k := diagKey{
			Provider: fmt.Sprint(env["provider"]),
			EventID:  uint16(toF(env["event_id"])),
			Opcode:   uint8(toF(env["opcode"])),
			Version:  uint8(toF(env["event_version"])),
		}
		counts[k]++
		if _, ok := samples[k]; !ok && len(samples) < 400 {
			samples[k] = string(data)
		}
		if selfName != "" && len(nameHits) < 10 && strings.Contains(strings.ToLower(string(data)), selfName) {
			nameHits = append(nameHits, string(data))
		}
	}
	<-done

	type row struct {
		k diagKey
		n int
	}
	rows := make([]row, 0, len(counts))
	for k, n := range counts {
		rows = append(rows, row{k, n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })

	t.Logf("=== ETW SHAPE: %d envelopes, %d distinct (provider,id,opcode,version) ===", total, len(rows))
	for i, r := range rows {
		name := diagProviderNames[strings.ToUpper(r.k.Provider)]
		cat := windowsCapabilityForETWEvent(name, r.k.EventID, r.k.Opcode)
		t.Logf("%4d x provider=%s name=%-10q id=%-4d opcode=%-4d ver=%d -> cat=%q",
			r.n, r.k.Provider, name, r.k.EventID, r.k.Opcode, r.k.Version, cat)
		if i < 40 {
			t.Logf("        sample: %s", truncate(samples[r.k], 600))
		}
	}
	for _, h := range nameHits {
		t.Logf("=== envelope naming the test binary: %s", truncate(h, 900))
	}
	t.Logf("=== capability summary: %+v", drv.CapabilityReport().Summary)
	for _, c := range drv.CapabilityReport().Categories {
		if c.Present {
			t.Logf("    %-20s attached=%v producing=%v observed=%d", c.Category, c.Attached, c.Producing, c.EventsObserved)
		}
	}
}

// diagProviderNames maps the envelope's provider GUID string back to the
// provider name, which is the key etwProviderNameForGUID uses.
var diagProviderNames = func() map[string]string {
	out := map[string]string{}
	for _, pc := range etwCoreProviders {
		out[strings.ToUpper(guidString(pc.guid))] = pc.name
	}
	for name, g := range map[string]windows.GUID{
		"WMI": wmiActivityGUID, "PowerShell": powershellGUID,
		"KernelObject": kernelObjectGUID, "BitsClient": bitsClientGUID,
		"TaskScheduler": taskSchedulerGUID, "AMSI": amsiGUID,
		"CodeIntegrity": codeIntegrityGUID, "AppLocker": appLockerGUID,
		"Defender": defenderETWGUID, "SecurityAuditing": securityAuditingGUID,
		"ThreatIntel": threatIntelGUID,
	} {
		out[strings.ToUpper(guidString(g))] = name
	}
	return out
}()

func toF(v interface{}) float64 {
	f, _ := v.(float64)
	return f
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
