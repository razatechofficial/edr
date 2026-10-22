//go:build windows && integration

package kernel

// Windows end-to-end monitoring proof, one subtest per capability category.
//
// These drive the ETW driver, which is the part of Windows kernel telemetry
// that needs only elevation. Starting a realtime trace session requires
// SeSystemProfilePrivilege, which an elevated session holds; GitHub-hosted
// windows runners do run elevated, so unlike the macOS tests these actually
// execute in CI.
//
// What these do NOT cover is the signed-driver tier: the WDM/minifilter paths
// (wdm_ioctl_windows.go, minifilter_ctl_windows.go) need a kernel-mode driver
// signed with an EV certificate and cross-signed by Microsoft, which no CI
// runner can load. Those categories are reported absent by the capability
// report rather than tested here. The Microsoft-Windows-Threat-Intelligence
// provider is the same kind of gap: it is restricted to binaries Microsoft has
// granted the TI ETW capability, so the categories only it can serve
// (memory_write, remote-thread and handle-open telemetry) are absent too.
//
// Every assertion matches on the PID of a child process this test started, not
// on a name. A hosted windows runner delivers tens of thousands of ETW events
// a minute from its own background work; a name match against that is a
// coin toss, and a PID is not.
//
// Run elevated with:
//
//	go test -tags=integration ./internal/kernel/ -run TestWindowsMonitoring -v

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
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// ---------------------------------------------------------------- helper mode

const (
	winHelperEnvVar = "EDR_MONITORING_ITEST_HELPER"
	winHelperArgVar = "EDR_MONITORING_ITEST_ARG"

	winActExec     = "exec"
	winActOpen     = "open"
	winActWrite    = "write"
	winActDelete   = "delete"
	winActRename   = "rename"
	winActDial     = "dial"
	winActListen   = "listen"
	winActDNS      = "dns"
	winActRegWrite = "regwrite"

	// itestRegKey is created under HKCU and removed again by the helper.
	// HKCU and a name of our own keeps this out of anything the runner
	// cares about.
	itestRegKey = `Software\EDRMonitoringIntegrationTest`
)

func init() {
	action := os.Getenv(winHelperEnvVar)
	if action == "" {
		return
	}
	if err := runWindowsHelperAction(action, os.Getenv(winHelperArgVar)); err != nil {
		fmt.Fprintf(os.Stderr, "helper %s failed: %v\n", action, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func runWindowsHelperAction(action, arg string) error {
	switch action {
	case winActExec:
		// Being executed is the event under test. Loading and
		// unloading this binary's own images is what proves
		// module_load and module_unload, and that happens without
		// doing anything further.
		return nil

	case winActOpen:
		f, err := os.Open(arg)
		if err != nil {
			return err
		}
		_, _ = f.Read(make([]byte, 1))
		return f.Close()

	case winActWrite:
		f, err := os.Create(arg)
		if err != nil {
			return err
		}
		if _, err := f.Write([]byte("edr monitoring integration test\r\n")); err != nil {
			f.Close()
			return err
		}
		return f.Close()

	case winActDelete:
		if err := os.WriteFile(arg, []byte("delete me\r\n"), 0o600); err != nil {
			return err
		}
		return os.Remove(arg)

	case winActRename:
		if err := os.WriteFile(arg, []byte("rename me\r\n"), 0o600); err != nil {
			return err
		}
		return os.Rename(arg, arg+".renamed")

	case winActDial:
		c, err := net.DialTimeout("tcp", arg, 5*time.Second)
		if err != nil {
			return err
		}
		if _, err := c.Write([]byte("ping")); err != nil {
			c.Close()
			return err
		}
		return c.Close()

	case winActListen:
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		fmt.Printf("PORT=%s\n", ln.Addr().String())
		os.Stdout.Sync()
		c, err := ln.Accept()
		if err != nil {
			ln.Close()
			return err
		}
		_, _ = c.Read(make([]byte, 16))
		_ = c.Close()
		return ln.Close()

	case winActDNS:
		// A name that does not resolve is fine: DnsClient emits
		// QuerySent and a failure event either way, and both carry the
		// name.
		_, _ = net.LookupHost(arg)
		return nil

	case winActRegWrite:
		k, _, err := registry.CreateKey(registry.CURRENT_USER, itestRegKey, registry.ALL_ACCESS)
		if err != nil {
			return err
		}
		if err := k.SetStringValue("itest_value", arg); err != nil {
			k.Close()
			return err
		}
		_ = k.DeleteValue("itest_value")
		k.Close()
		return registry.DeleteKey(registry.CURRENT_USER, itestRegKey)
	}
	return fmt.Errorf("unknown helper action %q", action)
}

// runWindowsHelper re-executes the test binary in helper mode and returns the
// PID the activity happened under.
func runWindowsHelper(t *testing.T, action, arg string) uint32 {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary for helper mode: %v", err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), winHelperEnvVar+"="+action, winHelperArgVar+"="+arg)
	out, err := cmd.CombinedOutput()
	if cmd.Process == nil {
		t.Fatalf("helper %s(%s) never started: %v", action, arg, err)
	}
	pid := uint32(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("helper %s(%s) [pid %d] failed: %v\n%s", action, arg, pid, err, out)
	}
	return pid
}

// startWindowsHelperListener starts the listen helper and returns the address
// it bound. Kernel-Network attributes an accept to the accepting process, so
// the listener has to be the child.
func startWindowsHelperListener(t *testing.T) (addr string, pid uint32, wait func()) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary for helper mode: %v", err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), winHelperEnvVar+"="+winActListen)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("helper stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting listen helper: %v", err)
	}
	pid = uint32(cmd.Process.Pid)

	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, 128)
		n, err := stdout.Read(buf)
		ch <- res{string(buf[:n]), err}
	}()
	select {
	case r := <-ch:
		if r.err != nil && r.line == "" {
			t.Fatalf("reading listen helper address: %v", r.err)
		}
		addr = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.line), "PORT="))
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("listen helper did not report an address within 15s")
	}
	return addr, pid, func() { _ = cmd.Wait() }
}

// ------------------------------------------------------------ driver bring-up

// startETWForTest applies the environment gates and returns a started driver
// with a tap on its ring buffer. It skips, never fails.
func startETWForTest(t *testing.T) (*ETWDriver, *etwTap) {
	t.Helper()

	drv, err := NewETWDriver("monitoring-integration-test")
	if err != nil {
		t.Skipf("MISSING PREREQUISITE: ETW driver could not be constructed: %v", err)
	}

	// 64 MiB: a hosted runner delivers several thousand ETW events a
	// second from its own background work, and a buffer that overflows
	// drops the record a subtest is about to look for.
	buf := NewRingBuffer(64 << 20)
	ctx, cancel := context.WithCancel(context.Background())

	if err := drv.Start(ctx, buf); err != nil {
		cancel()
		buf.Close()
		t.Skipf("MISSING PREREQUISITE: the ETW trace session could not be started: %v\n"+
			"A realtime kernel trace session needs an elevated process holding SeSystemProfilePrivilege. Run the test from an Administrator shell.", err)
	}

	t.Cleanup(func() {
		_ = drv.Stop()
		cancel()
		buf.Close()
	})

	// A session can start while individual providers fail to enable. That
	// is per provider, so report it and let each subtest gate on the
	// provider its category needs.
	var active, failed []string
	for _, h := range drv.ProviderHealthSnapshot() {
		if h.Active {
			active = append(active, h.Name)
			continue
		}
		failed = append(failed, h.Name+" ("+h.Error+")")
	}
	if len(active) == 0 {
		t.Skipf("MISSING PREREQUISITE: no ETW provider enabled. Failures: %s", strings.Join(failed, "; "))
	}
	t.Logf("ETW providers active: %s", strings.Join(active, ", "))
	if len(failed) > 0 {
		t.Logf("ETW providers failed: %s", strings.Join(failed, "; "))
	}
	return drv, newETWTap(t, buf)
}

func requireETWCategory(t *testing.T, drv *ETWDriver, cat CapabilityCategory) {
	t.Helper()
	c := findCapability(t, drv.CapabilityReport(), cat)
	if !c.Present {
		t.Skipf("MISSING PREREQUISITE: category %q has no ETW provider in this driver's provider set: %s", cat, c.Reason)
	}
	if !c.Attached {
		t.Skipf("MISSING PREREQUISITE: category %q is not attached: %s", cat, c.Reason)
	}
}

// ------------------------------------------------------------------ event tap

// etwEvent is one decoded JSON envelope from the ETW driver.
type etwEvent struct {
	Type      string `json:"type"`
	Provider  string `json:"provider"`
	EventID   uint16 `json:"event_id"`
	Version   uint8  `json:"event_version"`
	Opcode    uint8  `json:"opcode"`
	PID       uint32 `json:"pid"`
	ChildPID  uint32 `json:"child_pid"`
	ParentPID uint32 `json:"parent_pid"`
	ExitPID   uint32 `json:"exit_pid"`
	ImageName string `json:"image_name"`
	FileName  string `json:"file_name"`
	Path      string `json:"path"`
	KeyPath   string `json:"key_path"`
	ValueName string `json:"value_name"`
	Query     string `json:"query"`
	Operation string `json:"operation"`
	Raw       []byte `json:"-"`
}

func (e etwEvent) String() string {
	return fmt.Sprintf("etw{provider=%s id=%d ver=%d pid=%d type=%s name=%q}",
		etwShortProviderName(e.Provider), e.EventID, e.Version, e.PID, e.Type,
		e.ImageName+e.FileName+e.Path+e.KeyPath+e.Query)
}

// etwShortProviderName maps a provider GUID string to the driver's own name
// for it, so a failure message names "File" rather than a GUID.
func etwShortProviderName(guid string) string {
	for _, pc := range etwCoreProviders {
		if strings.EqualFold(guidString(pc.guid), guid) {
			return pc.name
		}
	}
	return guid
}

// fromProvider reports whether the event came from the named core provider.
func (e etwEvent) fromProvider(name string) bool {
	for _, pc := range etwCoreProviders {
		if pc.name == name {
			return strings.EqualFold(e.Provider, guidString(pc.guid))
		}
	}
	return false
}

// etwTap drains the ring buffer continuously into a bounded log. One shared
// draining reader is deliberate: with the buffer read only while a subtest is
// waiting, the runner's background activity fills it and the next subtest's
// record is dropped before it is read.
type etwTap struct {
	mu      sync.Mutex
	evs     []etwEvent
	dropped int
	counts  map[string]int
	stop    chan struct{}
	done    chan struct{}
}

const etwTapCap = 1 << 18

func newETWTap(t *testing.T, buf *RingBuffer) *etwTap {
	tp := &etwTap{
		counts: map[string]int{},
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go func() {
		defer close(tp.done)
		for {
			select {
			case <-tp.stop:
				return
			default:
			}
			data, err := buf.TryRead()
			if err != nil || data == nil {
				time.Sleep(time.Millisecond)
				continue
			}
			var ev etwEvent
			if json.Unmarshal(data, &ev) != nil {
				continue
			}
			ev.Raw = data
			tp.mu.Lock()
			if len(tp.evs) >= etwTapCap {
				half := etwTapCap / 2
				tp.evs = append(tp.evs[:0], tp.evs[half:]...)
				tp.dropped += half
			}
			tp.evs = append(tp.evs, ev)
			tp.counts[fmt.Sprintf("%s:%d", etwShortProviderName(ev.Provider), ev.EventID)]++
			tp.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		close(tp.stop)
		<-tp.done
	})
	return tp
}

func (tp *etwTap) mark() int {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.dropped + len(tp.evs)
}

// await polls for an event after mark that match accepts.
//
// Each pass examines only the events appended since the last one, and copies
// them out before matching. Re-scanning the whole window every 10ms under the
// mutex starved the draining goroutine once the window grew: the ring buffer
// filled, Write started returning ErrBufferFull, and subtests late in the run
// failed intermittently on events the kernel had produced and the buffer had
// dropped.
func (tp *etwTap) await(mark int, timeout time.Duration, match func(etwEvent) bool) (etwEvent, int, bool) {
	deadline := time.Now().Add(timeout)
	next := mark
	seen := 0
	var batch []etwEvent
	for {
		tp.mu.Lock()
		start := next - tp.dropped
		if start < 0 {
			start = 0
		}
		batch = batch[:0]
		if start < len(tp.evs) {
			batch = append(batch, tp.evs[start:]...)
		}
		next = tp.dropped + len(tp.evs)
		tp.mu.Unlock()

		seen += len(batch)
		for _, ev := range batch {
			if match(ev) {
				return ev, seen, true
			}
		}
		if time.Now().After(deadline) {
			return etwEvent{}, seen, false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// summary lists the twenty busiest (provider, event id) pairs the tap saw.
func (tp *etwTap) summary() string {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	keys := make([]string, 0, len(tp.counts))
	for k := range tp.counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return tp.counts[keys[i]] > tp.counts[keys[j]] })
	if len(keys) > 20 {
		keys = keys[:20]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "tap saw %d events (%d trimmed); busiest provider:id pairs:", len(tp.evs)+tp.dropped, tp.dropped)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%d", k, tp.counts[k])
	}
	return b.String()
}

// ------------------------------------------------------------ proof machinery

type etwProof struct {
	drv *ETWDriver
	tap *etwTap
	dir string
}

func (p *etwProof) tempPath(name string) string { return filepath.Join(p.dir, name) }

// listener binds a loopback TCP listener in the test process.
func (p *etwProof) listener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("MISSING PREREQUISITE: cannot bind a loopback TCP listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = c.Read(make([]byte, 64))
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func (p *etwProof) expect(t *testing.T, mark int, what string, match func(etwEvent) bool) etwEvent {
	t.Helper()
	ev, seen, ok := p.tap.await(mark, 25*time.Second, match)
	if !ok {
		t.Fatalf("no %s arrived within 25s after generating the activity (%d events seen in this window).\n%s\nThe provider serving this category is enabled, so the gap is in the event-id table or the decode path.",
			what, seen, p.tap.summary())
	}
	t.Logf("%s: %s", what, ev)
	return ev
}

func (p *etwProof) observed(t *testing.T, cat CapabilityCategory) uint64 {
	t.Helper()
	return findCapability(t, p.drv.CapabilityReport(), cat).EventsObserved
}

// ------------------------------------------------------------- category table

type etwCategoryProof struct {
	cat         CapabilityCategory
	unsupported string
	prove       func(t *testing.T, p *etwProof)
}

func etwCategoryProofs() []etwCategoryProof {
	return []etwCategoryProof{
		{
			cat: CapProcessExec,
			prove: func(t *testing.T, p *etwProof) {
				self, err := os.Executable()
				if err != nil {
					t.Fatalf("locating test binary: %v", err)
				}
				base := strings.ToLower(filepath.Base(self))
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActExec, "")
				// ProcessStart is attributed to the *parent* in the
				// event header; the new process is child_pid.
				ev := p.expect(t, m, fmt.Sprintf("ProcessStart for child pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderProcess) && e.EventID == 1 && e.ChildPID == pid
				})
				// The image name is the point of the version-aware
				// decode: reading a version 4 payload at the
				// version 0 offsets produced a plausible-looking
				// garbage path here for years.
				if !strings.Contains(strings.ToLower(ev.ImageName), base) {
					t.Errorf("ProcessStart image_name = %q, which does not name %q.\nThe payload is version %d; decodeKernelProcessStart must know that layout.",
						ev.ImageName, base, ev.Version)
				}
			},
		},
		{
			cat: CapProcessExit,
			prove: func(t *testing.T, p *etwProof) {
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActExec, "")
				p.expect(t, m, fmt.Sprintf("ProcessStop for pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderProcess) && e.EventID == 2 &&
						(e.ExitPID == pid || e.PID == pid)
				})
			},
		},
		{
			cat: CapModuleLoad,
			prove: func(t *testing.T, p *etwProof) {
				// A process start maps its own images; those are
				// the ImageLoad events, attributed to the loading
				// process.
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActExec, "")
				p.expect(t, m, fmt.Sprintf("ImageLoad for pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderProcess) && e.EventID == 5 && e.PID == pid
				})
			},
		},
		{
			cat: CapModuleUnload,
			prove: func(t *testing.T, p *etwProof) {
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActExec, "")
				p.expect(t, m, fmt.Sprintf("ImageUnload for pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderProcess) && e.EventID == 6 && e.PID == pid
				})
			},
		},
		{
			cat: CapFileOpen,
			prove: func(t *testing.T, p *etwProof) {
				path := p.tempPath("open-me.txt")
				runWindowsHelper(t, winActWrite, path)
				base := strings.ToLower(filepath.Base(path))
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActOpen, path)
				// Create carries FileName in its own template, so
				// the name is part of the match rather than
				// something checked afterwards: a Go binary
				// opens plenty of other files, and matching on
				// the pid alone picks up whichever it opened
				// first. A timeout here means the Create
				// template's FileName offset is wrong, which is
				// the defect that left every Kernel-File event
				// but Name pathless.
				p.expect(t, m, fmt.Sprintf("Kernel-File Create for pid %d naming %s", pid, base), func(e etwEvent) bool {
					return e.fromProvider(etwProviderFile) &&
						e.EventID == kernelFileEvtCreateID && e.PID == pid &&
						strings.Contains(strings.ToLower(e.FileName+e.Path), base)
				})
			},
		},
		{
			cat: CapFileWrite,
			prove: func(t *testing.T, p *etwProof) {
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActWrite, p.tempPath("write-me.txt"))
				// Write carries no file name of its own, only a
				// FileObject and a FileKey; the path, when there
				// is one, comes from the Name-event cache.
				ev := p.expect(t, m, fmt.Sprintf("Kernel-File Write for pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderFile) &&
						e.EventID == kernelFileEvtWriteID && e.PID == pid
				})
				t.Logf("write event resolved path: %q", ev.FileName+ev.Path)
			},
		},
		{
			cat: CapFileDelete,
			prove: func(t *testing.T, p *etwProof) {
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActDelete, p.tempPath("delete-me.txt"))
				p.expect(t, m, fmt.Sprintf("Kernel-File delete for pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderFile) && e.PID == pid &&
						(e.EventID == kernelFileEvtSetDeleteID || e.EventID == kernelFileEvtDeletePathID)
				})
			},
		},
		{
			cat: CapFileRename,
			prove: func(t *testing.T, p *etwProof) {
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActRename, p.tempPath("rename-me.txt"))
				p.expect(t, m, fmt.Sprintf("Kernel-File rename for pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderFile) && e.PID == pid &&
						(e.EventID == kernelFileEvtRenameID || e.EventID == kernelFileEvtRenamePathID)
				})
			},
		},
		{
			cat:         CapFilePermission,
			unsupported: "Kernel-File does emit a pair of security-descriptor events, but which of the two is the set and which is the query cannot be told from the event id alone, and crediting a security-descriptor read as a permission change would be a wrong row. Resolving it needs TdhGetEventInformation to read the template by name, which this driver does not do.",
		},
		{
			cat: CapNetworkConnect,
			prove: func(t *testing.T, p *etwProof) {
				addr := p.listener(t)
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActDial, addr)
				p.expect(t, m, fmt.Sprintf("Kernel-Network connect for pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderNetwork) && e.PID == pid &&
						(e.EventID == kernelNetEvtConnect4 || e.EventID == kernelNetEvtConnect6)
				})
			},
		},
		{
			cat: CapNetworkAccept,
			prove: func(t *testing.T, p *etwProof) {
				addr, pid, wait := startWindowsHelperListener(t)
				m := p.tap.mark()
				c, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					t.Fatalf("dialing the helper listener at %s: %v", addr, err)
				}
				_, _ = c.Write([]byte("ping"))
				_ = c.Close()
				p.expect(t, m, fmt.Sprintf("Kernel-Network accept for listener pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderNetwork) && e.PID == pid &&
						(e.EventID == kernelNetEvtAccept4 || e.EventID == kernelNetEvtAccept6)
				})
				wait()
			},
		},
		{
			cat:         CapNetworkBind,
			unsupported: "Microsoft-Windows-Kernel-Network has no bind template; its TCP and UDP blocks cover data transfer, connect, disconnect, accept, reconnect and retransmit only. Bind telemetry on Windows needs a WFP callout driver, which is the signed-driver tier.",
		},
		{
			cat: CapNetworkClose,
			prove: func(t *testing.T, p *etwProof) {
				addr := p.listener(t)
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActDial, addr)
				p.expect(t, m, fmt.Sprintf("Kernel-Network disconnect for pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderNetwork) && e.PID == pid &&
						(e.EventID == kernelNetEvtDisconnect4 || e.EventID == kernelNetEvtDisconnect6)
				})
			},
		},
		{
			cat: CapNetworkDNS,
			prove: func(t *testing.T, p *etwProof) {
				name := fmt.Sprintf("edr-itest-%d.example.com", time.Now().UnixNano())
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActDNS, name)
				// DnsClient events are emitted by whichever
				// component resolves, which is not always the
				// querying process, so the name is the attribution
				// here and the pid is only logged.
				ev := p.expect(t, m, fmt.Sprintf("DnsClient event naming %s (queried by pid %d)", name, pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderDNS) &&
						strings.Contains(strings.ToLower(e.Query), strings.ToLower(name))
				})
				t.Logf("dns event pid=%d (querying helper was %d)", ev.PID, pid)
			},
		},
		{
			cat: CapRegistryWrite,
			prove: func(t *testing.T, p *etwProof) {
				m := p.tap.mark()
				pid := runWindowsHelper(t, winActRegWrite, "edr-itest")
				ev := p.expect(t, m, fmt.Sprintf("Kernel-Registry SetValue for pid %d", pid), func(e etwEvent) bool {
					return e.fromProvider(etwProviderRegistry) && e.PID == pid &&
						e.EventID == kernelRegistryEvtSetValue
				})
				// operation and value_name only appear when the
				// decoder switches on the event id; keyed on the
				// opcode, as it was, the SetValue branch never ran.
				if ev.Operation != "set_value" {
					t.Errorf("SetValue event reports operation %q, want set_value", ev.Operation)
				}
				// Exactly "itest_value": reading the value name two
				// bytes late, which the old offset did, yields
				// "test_value" and would pass a Contains check.
				if ev.ValueName != "itest_value" {
					t.Errorf("SetValue event reports value_name %q, want itest_value", ev.ValueName)
				}
				// SetValueKey carries no key path of its own; this
				// comes from the KeyObject the CreateKey event
				// seeded, so it also exercises that cache.
				if !strings.Contains(ev.KeyPath, "EDRMonitoringIntegrationTest") {
					t.Errorf("SetValue event reports key_path %q, which does not name the key the helper wrote; the KeyObject cache did not resolve it", ev.KeyPath)
				}
			},
		},
		{
			cat:         CapProcessFork,
			unsupported: "Windows has no fork. Process creation is ProcessStart, which process_exec already covers; reporting the same event under a second category would double-count it.",
		},
		{
			cat:         CapCredentialChange,
			unsupported: "None of the kernel providers this driver enables emits credential changes. Microsoft-Windows-Security-Auditing does (4672, 4720, 4728 and friends), and the driver enables it, but it is decoded opaquely with no per-event-id classification, so there is nothing to credit this category from without inventing a mapping.",
		},
		{
			cat:         CapNamespaceChange,
			unsupported: "The Windows equivalent is a job object or a server silo, and no provider in the enabled set reports either.",
		},
		{
			cat:         CapPtrace,
			unsupported: "Handle-open telemetry (the ObOpenProcess analogue of ptrace) comes from Microsoft-Windows-Threat-Intelligence, which only a binary Microsoft has granted the TI ETW capability can enable. etw_ti_windows.go probes for it and reports the outcome separately; no hosted runner has it.",
		},
		{
			cat:         CapSignal,
			unsupported: "Windows has no signals. The nearest analogue, a forced process termination, is not reported by any provider in the enabled set.",
		},
		{
			cat:         CapMemoryWrite,
			unsupported: "WriteVirtualMemory and remote-thread creation come from Microsoft-Windows-Threat-Intelligence, which needs the TI ETW capability no hosted runner has.",
		},
		{
			cat:         CapMount,
			unsupported: "Volume mount and dismount telemetry needs a filesystem filter or the volume-change WMI classes; no provider in the enabled set reports it.",
		},
		{
			cat:         CapScheduler,
			unsupported: "Context-switch sampling needs the NT Kernel Logger's CSwitch class, which is a single system-wide session this driver does not take. Kernel-Process's ThreadStart and ThreadStop are thread lifecycle, not scheduling.",
		},
		{
			cat:         CapTLSMetadata,
			unsupported: "TLS handshake metadata would come from Microsoft-Windows-Schannel-Events, which this driver does not enable.",
		},
	}
}

// TestWindowsMonitoringCategories proves one capability category per subtest.
//
// All subtests share one driver and one draining reader. A realtime ETW
// session takes a second or two to come up per provider, and only one ETW
// driver instance can be active at a time anyway.
// TestWindowsMonitoringCategoryTableCoversEveryCategory needs no ETW session,
// so it runs even where one cannot be started.
func TestWindowsMonitoringCategoryTableCoversEveryCategory(t *testing.T) {
	proofs := etwCategoryProofs()
	covered := make(map[CapabilityCategory]bool, len(proofs))
	for _, pr := range proofs {
		if covered[pr.cat] {
			t.Errorf("category %q has more than one proof case", pr.cat)
		}
		covered[pr.cat] = true
		if pr.unsupported == "" && pr.prove == nil {
			t.Errorf("category %q has neither a proof nor an unsupported reason", pr.cat)
		}
	}
	for _, cat := range CanonicalCapabilityCategories {
		if !covered[cat] {
			t.Errorf("capability category %q has no proof case in etwCategoryProofs; add one, or add it with an unsupported reason if the enabled ETW provider set genuinely cannot serve it", cat)
		}
	}
	t.Logf("%d proof cases for %d canonical categories", len(proofs), len(CanonicalCapabilityCategories))
}

func TestWindowsMonitoringCategories(t *testing.T) {
	drv, tap := startETWForTest(t)

	for _, pr := range etwCategoryProofs() {
		pr := pr
		t.Run(string(pr.cat), func(t *testing.T) {
			c := findCapability(t, drv.CapabilityReport(), pr.cat)

			if pr.unsupported != "" {
				if c.Present {
					t.Fatalf("category %q is marked unsupported here but the capability report says present=true with mechanism %q; one of the two is wrong", pr.cat, c.Mechanism)
				}
				if c.Reason == "" {
					t.Errorf("category %q is absent with no reason; the console shows this row and needs to say why", pr.cat)
				}
				t.Skipf("NOT SUPPORTED BY THE ENABLED ETW PROVIDER SET: %s", pr.unsupported)
			}

			requireETWCategory(t, drv, pr.cat)

			p := &etwProof{drv: drv, tap: tap, dir: t.TempDir()}
			pr.prove(t, p)

			if c := findCapability(t, drv.CapabilityReport(), pr.cat); !c.Producing {
				t.Errorf("an event for %q arrived but CapabilityReport says it is not producing: %+v", pr.cat, c)
			}
		})
	}

	t.Logf("final capability summary on this host: %+v", drv.CapabilityReport().Summary)
}

// TestWindowsMonitoringCapabilityReportMatchesProviderHealth asserts the
// report an operator reads agrees with the live provider health records.
func TestWindowsMonitoringCapabilityReportMatchesProviderHealth(t *testing.T) {
	drv, _ := startETWForTest(t)

	activeProviders := make(map[string]bool)
	for _, h := range drv.ProviderHealthSnapshot() {
		if h.Active {
			activeProviders[h.Name] = true
		}
	}

	rep := drv.CapabilityReport()
	if !rep.DriverRunning {
		t.Fatal("report says driver_running=false for a driver that started")
	}
	for _, c := range rep.Categories {
		if c.Attached {
			for _, hook := range c.Attachments {
				if !activeProviders[hook] {
					t.Errorf("category %q reports attachment %q, but that provider is not active in ProviderHealthSnapshot", c.Category, hook)
				}
			}
		}
		if !c.Present && c.Reason == "" {
			t.Errorf("category %q is absent with no reason", c.Category)
		}
	}
	t.Logf("capability summary on this host: %+v", rep.Summary)
}
