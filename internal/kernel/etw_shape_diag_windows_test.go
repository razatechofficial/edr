//go:build windows && integration

package kernel

// TEMPORARY DIAGNOSTIC — delete once the Windows ETW event-id tables are
// fixed. It asserts nothing.
//
// windowsCapabilityForETWEvent and the Kernel-File / Kernel-Network decoders
// were written from the NT Kernel Logger MOF opcode numbering, not from the
// manifest providers this driver actually enables, and nobody had ever
// compared them against a live provider set. This runs one labelled burst of
// activity per category with a quiet baseline window, so which event id means
// "write", "delete", "rename", "connect", "accept" or "close" can be read off
// the counts instead of guessed.

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type diagKey struct {
	Provider string
	EventID  uint16
	Opcode   uint8
	Version  uint8
}

type diagCollector struct {
	mu       sync.Mutex
	label    string
	counts   map[string]map[diagKey]int
	procHex  []string
	wantPIDs map[uint32]bool
}

func (c *diagCollector) setLabel(l string) {
	c.mu.Lock()
	c.label = l
	c.mu.Unlock()
}

func (c *diagCollector) record(hdr etwEventHeader, ud []byte) {
	name := diagProviderNames[hdr.ProviderId]
	if name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.label == "" {
		return
	}
	k := diagKey{
		Provider: name,
		EventID:  hdr.EventDescriptor.Id,
		Opcode:   hdr.EventDescriptor.Opcode,
		Version:  hdr.EventDescriptor.Version,
	}
	w := c.counts[c.label]
	if w == nil {
		w = map[diagKey]int{}
		c.counts[c.label] = w
	}
	w[k]++

	// Dump payloads whose field layout the decoders guess at, so the real
	// one can be read off a real record instead of recalled.
	dump := (name == etwProviderProcess && k.EventID == 1) ||
		(name == etwProviderRegistry && (k.EventID == 1 || k.EventID == 5)) ||
		(name == etwProviderFile && (k.EventID == 12 || k.EventID == 16))
	if dump && len(c.procHex) < 24 && len(ud) > 0 {
		c.procHex = append(c.procHex, fmt.Sprintf("%s id=%d ver=%d len=%d hdr.pid=%d\n%s",
			name, k.EventID, k.Version, len(ud), hdr.ProcessId, hex.Dump(ud)))
	}
}

var diagProviderNames = func() map[windows.GUID]string {
	out := map[windows.GUID]string{}
	for _, pc := range etwCoreProviders {
		out[pc.guid] = pc.name
	}
	return out
}()

func TestWindowsETWEventShapeDiagnostic(t *testing.T) {
	drv, err := NewETWDriver("etw-shape-diagnostic")
	if err != nil {
		t.Skipf("MISSING PREREQUISITE: ETW driver could not be constructed: %v", err)
	}
	col := &diagCollector{counts: map[string]map[diagKey]int{}, wantPIDs: map[uint32]bool{}}
	etwRawRecordHook = col.record
	t.Cleanup(func() { etwRawRecordHook = nil })

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

	// Keep the ring buffer drained; it is not what this test reads, but a
	// full buffer changes the driver's behaviour.
	drain := make(chan struct{})
	go func() {
		for {
			select {
			case <-drain:
				return
			default:
			}
			if data, err := buf.TryRead(); err != nil || data == nil {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	t.Cleanup(func() { close(drain) })

	dir := t.TempDir()
	self, _ := os.Executable()
	const burst = 40

	actions := []struct {
		name string
		run  func()
	}{
		{"baseline", func() { time.Sleep(2 * time.Second) }},
		{"exec", func() {
			for i := 0; i < 10; i++ {
				cmd := exec.Command(self)
				cmd.Env = append(os.Environ(), winHelperEnvVar+"=exec")
				_ = cmd.Run()
			}
		}},
		{"file_create_write", func() {
			for i := 0; i < burst; i++ {
				p := filepath.Join(dir, fmt.Sprintf("w%03d.txt", i))
				f, err := os.Create(p)
				if err != nil {
					continue
				}
				_, _ = f.Write([]byte("edr etw shape diagnostic payload\r\n"))
				_ = f.Close()
			}
		}},
		{"file_rename", func() {
			for i := 0; i < burst; i++ {
				_ = os.Rename(filepath.Join(dir, fmt.Sprintf("w%03d.txt", i)),
					filepath.Join(dir, fmt.Sprintf("r%03d.txt", i)))
			}
		}},
		{"file_delete", func() {
			for i := 0; i < burst; i++ {
				_ = os.Remove(filepath.Join(dir, fmt.Sprintf("r%03d.txt", i)))
			}
		}},
		{"file_setacl", func() {
			p := filepath.Join(dir, "acl.txt")
			_ = os.WriteFile(p, []byte("acl"), 0o600)
			for i := 0; i < 10; i++ {
				_ = exec.Command("icacls", p, "/grant", "Everyone:(R)").Run()
				_ = exec.Command("icacls", p, "/remove", "Everyone").Run()
			}
		}},
		{"net_connect_accept_close", func() {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return
			}
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					_ = c.Close()
				}
			}()
			for i := 0; i < burst; i++ {
				c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
				if err == nil {
					_, _ = c.Write([]byte("x"))
					_ = c.Close()
				}
			}
			_ = ln.Close()
		}},
		{"net_udp_bind_send", func() {
			for i := 0; i < burst; i++ {
				c, err := net.Dial("udp", "127.0.0.1:9")
				if err != nil {
					continue
				}
				_, _ = c.Write([]byte("x"))
				_ = c.Close()
			}
		}},
		{"registry_write", func() {
			k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\EDRShapeDiag`, registry.ALL_ACCESS)
			if err != nil {
				return
			}
			for i := 0; i < burst; i++ {
				_ = k.SetStringValue(fmt.Sprintf("v%03d", i), "edr shape diagnostic")
			}
			k.Close()
			_ = registry.DeleteKey(registry.CURRENT_USER, `Software\EDRShapeDiag`)
		}},
		{"dns", func() {
			for i := 0; i < 10; i++ {
				_, _ = net.LookupHost(fmt.Sprintf("edr-diag-%d.example.com", i))
			}
		}},
	}

	for _, a := range actions {
		// Quiet period: let the previous burst's events land unlabelled.
		col.setLabel("")
		time.Sleep(1500 * time.Millisecond)
		col.setLabel(a.name)
		a.run()
		time.Sleep(2500 * time.Millisecond)
	}
	col.setLabel("")

	col.mu.Lock()
	defer col.mu.Unlock()
	for _, a := range actions {
		w := col.counts[a.name]
		type row struct {
			k diagKey
			n int
		}
		rows := make([]row, 0, len(w))
		for k, n := range w {
			rows = append(rows, row{k, n})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
		t.Logf("=== WINDOW %s (%d distinct)", a.name, len(rows))
		for _, r := range rows {
			if r.n < 3 {
				continue
			}
			t.Logf("    %5d x %-10s id=%-5d opcode=%-4d ver=%d -> cat=%q",
				r.n, r.k.Provider, r.k.EventID, r.k.Opcode, r.k.Version,
				windowsCapabilityForETWEvent(r.k.Provider, r.k.EventID, r.k.Opcode))
		}
	}
	for i, h := range col.procHex {
		t.Logf("=== payload %d\n%s", i, h)
	}
}
