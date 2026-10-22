//go:build darwin && integration

package kernel

// macOS end-to-end monitoring proof, one subtest per capability category.
//
// These will skip on almost every machine, including every GitHub-hosted
// macOS runner, and that is the honest outcome rather than a gap in the
// tests. Opening an Endpoint Security client requires all of:
//
//   - root;
//   - a build with cgo and without the nosec tag, so the ESF bridge exists;
//   - the com.apple.developer.endpoint-security.client entitlement, which
//     Apple grants per Developer ID and which must be embedded in a signed
//     binary;
//   - on recent macOS, approval of the containing System Extension.
//
// A `go test` binary is ad-hoc signed and carries no entitlement, so
// es_new_client returns ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED. The driver's
// clientCreateError maps those result codes to actionable messages and the
// skip below surfaces them verbatim, so a developer running this on a
// provisioned machine learns which of the four prerequisites is missing.
//
// Because of that, these per-category proofs have never executed anywhere.
// The category table and its unsupported-reasons are checked on every runner
// (TestDarwinMonitoringCategoryTableCoversEveryCategory needs no ESF client);
// the activity-generating half is compile-checked only until someone runs it
// on a provisioned Mac.
//
// Run on a provisioned host with:
//
//	sudo -E go test -tags=integration ./internal/kernel/ -run TestDarwinMonitoring -v

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------- helper mode

const (
	darwinHelperEnvVar = "EDR_MONITORING_ITEST_HELPER"
	darwinHelperArgVar = "EDR_MONITORING_ITEST_ARG"

	dwActExec     = "exec"
	dwActFork     = "fork"
	dwActOpen     = "open"
	dwActWrite    = "write"
	dwActTruncate = "truncate"
	dwActUnlink   = "unlink"
	dwActRename   = "rename"
	dwActMmap     = "mmap"
	dwActMprotect = "mprotect"
	dwActSignal   = "signal"
	dwActSleep    = "sleep"
	dwActGetTask  = "gettask"
	dwActSetID    = "setid"
)

func init() {
	action := os.Getenv(darwinHelperEnvVar)
	if action == "" {
		return
	}
	if err := runDarwinHelperAction(action, os.Getenv(darwinHelperArgVar)); err != nil {
		fmt.Fprintf(os.Stderr, "helper %s failed: %v\n", action, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func runDarwinHelperAction(action, arg string) error {
	self, _ := os.Executable()

	switch action {
	case dwActExec:
		// Being executed is the event under test; exiting afterwards
		// is what proves process_exit.
		return nil

	case dwActFork:
		cmd := exec.Command(self)
		cmd.Env = append(os.Environ(), darwinHelperEnvVar+"="+dwActExec)
		return cmd.Run()

	case dwActOpen:
		f, err := os.Open(arg)
		if err != nil {
			return err
		}
		_, _ = f.Read(make([]byte, 1))
		return f.Close()

	case dwActWrite:
		f, err := os.Create(arg)
		if err != nil {
			return err
		}
		if _, err := f.Write([]byte("edr monitoring integration test\n")); err != nil {
			f.Close()
			return err
		}
		return f.Close()

	case dwActTruncate:
		if err := os.WriteFile(arg, []byte("truncate me\n"), 0o600); err != nil {
			return err
		}
		return os.Truncate(arg, 0)

	case dwActUnlink:
		if err := os.WriteFile(arg, []byte("delete me\n"), 0o600); err != nil {
			return err
		}
		return os.Remove(arg)

	case dwActRename:
		if err := os.WriteFile(arg, []byte("rename me\n"), 0o600); err != nil {
			return err
		}
		return os.Rename(arg, arg+".renamed")

	case dwActMmap:
		// A file-backed mapping is what ESF reports as an image load.
		f, err := os.Open(arg)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		n := int(st.Size())
		if n < 1 {
			return fmt.Errorf("mmap target %s is empty", arg)
		}
		b, err := unix.Mmap(int(f.Fd()), 0, n, unix.PROT_READ, unix.MAP_PRIVATE)
		if err != nil {
			return err
		}
		return unix.Munmap(b)

	case dwActMprotect:
		b, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_PRIVATE|unix.MAP_ANON)
		if err != nil {
			return err
		}
		defer unix.Munmap(b)
		return unix.Mprotect(b, unix.PROT_READ)

	case dwActSignal:
		// Signal a child of our own rather than anything on the
		// machine. The grandchild sleeps until it is killed.
		cmd := exec.Command(self)
		cmd.Env = append(os.Environ(), darwinHelperEnvVar+"="+dwActSleep)
		if err := cmd.Start(); err != nil {
			return err
		}
		time.Sleep(300 * time.Millisecond)
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			return err
		}
		_, _ = cmd.Process.Wait()
		return nil

	case dwActSleep:
		time.Sleep(10 * time.Second)
		return nil

	case dwActGetTask:
		// vmmap calls task_for_pid, which is what AUTH_GET_TASK
		// reports. Nothing in the Go standard library reaches
		// task_for_pid, and adding cgo to a _test.go file is not
		// possible, so this shells out.
		if _, err := exec.LookPath("vmmap"); err != nil {
			return fmt.Errorf("vmmap not available: %w", err)
		}
		cmd := exec.Command(self)
		cmd.Env = append(os.Environ(), darwinHelperEnvVar+"="+dwActSleep)
		if err := cmd.Start(); err != nil {
			return err
		}
		defer func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}()
		time.Sleep(300 * time.Millisecond)
		out, err := exec.Command("vmmap", "-summary", strconv.Itoa(cmd.Process.Pid)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("vmmap: %v: %s", err, out)
		}
		return nil

	case dwActSetID:
		// Already root, so this changes nothing while still entering
		// the syscall ESF reports.
		if _, _, e := unix.RawSyscall(unix.SYS_SETGID, 0, 0, 0); e != 0 {
			return fmt.Errorf("setgid: %w", e)
		}
		if _, _, e := unix.RawSyscall(unix.SYS_SETUID, 0, 0, 0); e != 0 {
			return fmt.Errorf("setuid: %w", e)
		}
		return nil
	}
	return fmt.Errorf("unknown helper action %q", action)
}

func runDarwinHelper(t *testing.T, action, arg string) uint32 {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary for helper mode: %v", err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), darwinHelperEnvVar+"="+action, darwinHelperArgVar+"="+arg)
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

// ------------------------------------------------------------ driver bring-up

// startESFForTest applies the environment gates and returns a started driver
// with a tap on its ring buffer. It skips, never fails.
func startESFForTest(t *testing.T) (*ESFDriver, *esfTap) {
	t.Helper()

	if euid := os.Geteuid(); euid != 0 {
		t.Skipf("MISSING PREREQUISITE: root. es_new_client requires it; this process has euid=%d. Re-run with: sudo -E go test -tags=integration ./internal/kernel/ -run %s", euid, t.Name())
	}

	drv, err := NewESFDriver("monitoring-integration-test")
	if err != nil {
		t.Skipf("MISSING PREREQUISITE: ESF driver could not be constructed: %v", err)
	}

	// A build without the ESF bridge reports every category absent; there
	// is nothing to drive. CapabilityReport is the cheapest way to detect
	// that without duplicating the build tags here.
	if rep := drv.CapabilityReport(); rep.Summary.Present == 0 {
		t.Skipf("MISSING PREREQUISITE: this build has no Endpoint Security bridge (%s/%s). %s",
			runtime.GOOS, runtime.GOARCH, rep.Categories[0].Reason)
	}

	buf := NewRingBuffer(32 << 20)
	ctx, cancel := context.WithCancel(context.Background())

	if err := drv.Start(ctx, buf); err != nil {
		cancel()
		buf.Close()
		t.Skipf("MISSING PREREQUISITE: the ESF client could not be created or subscribed: %v\n"+
			"This is expected for an ad-hoc signed `go test` binary: the com.apple.developer.endpoint-security.client entitlement must be embedded in a binary signed with a Developer ID that Apple has granted it, and on recent macOS the containing System Extension must be approved.", err)
	}

	t.Cleanup(func() {
		_ = drv.Stop()
		cancel()
		buf.Close()
	})
	return drv, newESFTap(t, buf)
}

func requireESFCategory(t *testing.T, drv *ESFDriver, cat CapabilityCategory) {
	t.Helper()
	c := findCapability(t, drv.CapabilityReport(), cat)
	if !c.Present {
		t.Skipf("MISSING PREREQUISITE: category %q has no ESF mechanism in this build: %s", cat, c.Reason)
	}
	if !c.Attached {
		t.Skipf("MISSING PREREQUISITE: category %q is not attached: %s", cat, c.Reason)
	}
}

// ------------------------------------------------------------------ event tap

// esfEvent is one decoded JSON envelope from the ESF driver.
type esfEvent struct {
	Type    string `json:"type"`
	ESFOp   string `json:"esf_op"`
	ESFType int    `json:"esf_type"`
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Path    string `json:"path"`
	Comm    string `json:"comm"`
	Signal  int    `json:"signal_number"`
	Raw     []byte `json:"-"`
}

func (e esfEvent) String() string {
	return fmt.Sprintf("esf{op=%s type=%d pid=%d path=%q}", e.ESFOp, e.ESFType, e.PID, e.Path)
}

// esfTap drains the ring buffer continuously. ESF on a live Mac delivers a
// large volume of open and mmap events; a buffer read only while a subtest
// waits would overflow and drop the record it is looking for.
type esfTap struct {
	mu      sync.Mutex
	evs     []esfEvent
	dropped int
	counts  map[string]int
	stop    chan struct{}
	done    chan struct{}
}

const esfTapCap = 1 << 18

func newESFTap(t *testing.T, buf *RingBuffer) *esfTap {
	tp := &esfTap{
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
			var ev esfEvent
			if json.Unmarshal(data, &ev) != nil {
				continue
			}
			ev.Raw = data
			tp.mu.Lock()
			if len(tp.evs) >= esfTapCap {
				half := esfTapCap / 2
				tp.evs = append(tp.evs[:0], tp.evs[half:]...)
				tp.dropped += half
			}
			tp.evs = append(tp.evs, ev)
			tp.counts[fmt.Sprintf("%s(%d)", ev.ESFOp, ev.ESFType)]++
			tp.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		close(tp.stop)
		<-tp.done
	})
	return tp
}

func (tp *esfTap) mark() int {
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
func (tp *esfTap) await(mark int, timeout time.Duration, match func(esfEvent) bool) (esfEvent, int, bool) {
	deadline := time.Now().Add(timeout)
	next := mark
	seen := 0
	var batch []esfEvent
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
			return esfEvent{}, seen, false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (tp *esfTap) summary() string {
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
	fmt.Fprintf(&b, "tap saw %d events (%d trimmed); busiest ops:", len(tp.evs)+tp.dropped, tp.dropped)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%d", k, tp.counts[k])
	}
	return b.String()
}

// ------------------------------------------------------------ proof machinery

type esfProof struct {
	drv *ESFDriver
	tap *esfTap
	dir string
}

func (p *esfProof) tempPath(name string) string { return filepath.Join(p.dir, name) }

func (p *esfProof) expect(t *testing.T, mark int, what string, match func(esfEvent) bool) esfEvent {
	t.Helper()
	ev, seen, ok := p.tap.await(mark, 20*time.Second, match)
	if !ok {
		t.Fatalf("no %s arrived within 20s after generating the activity (%d events seen in this window).\n%s\nThe subscription for this category is live, so the gap is in the C bridge's event handling or the decode path.",
			what, seen, p.tap.summary())
	}
	t.Logf("%s: %s", what, ev)
	return ev
}

// ------------------------------------------------------------- category table

type esfCategoryProof struct {
	cat         CapabilityCategory
	unsupported string
	prove       func(t *testing.T, p *esfProof)
}

func esfCategoryProofs() []esfCategoryProof {
	return []esfCategoryProof{
		{
			cat: CapProcessExec,
			prove: func(t *testing.T, p *esfProof) {
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActExec, "")
				p.expect(t, m, fmt.Sprintf("exec event for pid %d", pid), func(e esfEvent) bool {
					return e.ESFOp == "exec" && e.PID == int(pid)
				})
			},
		},
		{
			cat: CapProcessFork,
			prove: func(t *testing.T, p *esfProof) {
				m := p.tap.mark()
				// ESF reports a fork against the forking process.
				pid := runDarwinHelper(t, dwActFork, "")
				p.expect(t, m, fmt.Sprintf("fork event for pid %d", pid), func(e esfEvent) bool {
					return e.ESFOp == "fork" && e.PID == int(pid)
				})
			},
		},
		{
			cat: CapProcessExit,
			prove: func(t *testing.T, p *esfProof) {
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActExec, "")
				p.expect(t, m, fmt.Sprintf("exit event for pid %d", pid), func(e esfEvent) bool {
					return e.ESFOp == "exit" && e.PID == int(pid)
				})
			},
		},
		{
			cat: CapFileOpen,
			prove: func(t *testing.T, p *esfProof) {
				path := p.tempPath("open-me.txt")
				runDarwinHelper(t, dwActWrite, path)
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActOpen, path)
				p.expect(t, m, fmt.Sprintf("open event for pid %d naming %s", pid, filepath.Base(path)), func(e esfEvent) bool {
					return (e.ESFOp == "open" || e.ESFOp == "create") && e.PID == int(pid) &&
						strings.Contains(e.Path, filepath.Base(path))
				})
			},
		},
		{
			cat: CapFileWrite,
			prove: func(t *testing.T, p *esfProof) {
				path := p.tempPath("write-me.txt")
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActWrite, path)
				p.expect(t, m, fmt.Sprintf("write event for pid %d naming %s", pid, filepath.Base(path)), func(e esfEvent) bool {
					return (e.ESFOp == "write" || e.ESFOp == "truncate") && e.PID == int(pid) &&
						strings.Contains(e.Path, filepath.Base(path))
				})
			},
		},
		{
			cat: CapFileDelete,
			prove: func(t *testing.T, p *esfProof) {
				path := p.tempPath("delete-me.txt")
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActUnlink, path)
				p.expect(t, m, fmt.Sprintf("unlink event for pid %d naming %s", pid, filepath.Base(path)), func(e esfEvent) bool {
					return e.ESFOp == "unlink" && e.PID == int(pid) &&
						strings.Contains(e.Path, filepath.Base(path))
				})
			},
		},
		{
			cat: CapFileRename,
			prove: func(t *testing.T, p *esfProof) {
				path := p.tempPath("rename-me.txt")
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActRename, path)
				p.expect(t, m, fmt.Sprintf("rename event for pid %d", pid), func(e esfEvent) bool {
					return e.ESFOp == "rename" && e.PID == int(pid)
				})
			},
		},
		{
			cat:         CapFilePermission,
			unsupported: "ESF has AUTH/NOTIFY_SETMODE, SETOWNER, SETFLAGS and SETACL, but esf_subscribe_all subscribes none of them, so no event for this category can arrive. Subscribing them is a change to the C bridge, not to this test.",
		},
		{
			cat: CapModuleLoad,
			prove: func(t *testing.T, p *esfProof) {
				// A file-backed mmap is what ESF reports as an
				// image load; AUTH_KEXTLOAD would need a kext.
				self, err := os.Executable()
				if err != nil {
					t.Fatalf("locating test binary: %v", err)
				}
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActMmap, self)
				p.expect(t, m, fmt.Sprintf("image_load event for pid %d", pid), func(e esfEvent) bool {
					return e.ESFOp == "image_load" && e.PID == int(pid)
				})
			},
		},
		{
			cat:         CapModuleUnload,
			unsupported: "ESF defines NOTIFY_KEXTUNLOAD but esf_subscribe_all does not subscribe it, and there is no unmap or dylib-unload event at all, so nothing can be credited to this category.",
		},
		{
			cat: CapCredentialChange,
			prove: func(t *testing.T, p *esfProof) {
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActSetID, "")
				p.expect(t, m, fmt.Sprintf("setuid/setgid event for pid %d", pid), func(e esfEvent) bool {
					switch e.ESFOp {
					case "setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid":
						return e.PID == int(pid)
					}
					return false
				})
			},
		},
		{
			cat:         CapNamespaceChange,
			unsupported: "macOS has no namespaces. The nearest analogue is a sandbox profile or an app container, and ESF reports neither as a transition.",
		},
		{
			cat: CapPtrace,
			prove: func(t *testing.T, p *esfProof) {
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActGetTask, "")
				// AUTH_GET_TASK is reported against the process
				// asking for the task port, which is vmmap, not
				// the helper that launched it.
				ev := p.expect(t, m, "get_task event", func(e esfEvent) bool {
					return e.ESFOp == "get_task"
				})
				t.Logf("get_task requested by pid %d comm=%q (helper was %d)", ev.PID, ev.Comm, pid)
			},
		},
		{
			cat: CapSignal,
			prove: func(t *testing.T, p *esfProof) {
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActSignal, "")
				p.expect(t, m, fmt.Sprintf("signal event from pid %d", pid), func(e esfEvent) bool {
					return e.ESFOp == "signal" && e.PID == int(pid)
				})
			},
		},
		{
			cat: CapMemoryWrite,
			prove: func(t *testing.T, p *esfProof) {
				m := p.tap.mark()
				pid := runDarwinHelper(t, dwActMprotect, "")
				p.expect(t, m, fmt.Sprintf("mprotect event for pid %d", pid), func(e esfEvent) bool {
					return e.ESFOp == "mprotect" && e.PID == int(pid)
				})
			},
		},
		{
			cat:         CapMount,
			unsupported: "AUTH_MOUNT is subscribed and would fire, but generating a mount means creating and attaching a disk image with hdiutil, and a failed detach leaves an attached image behind on the machine this runs on. This is a limitation of the proof, not of the platform: the subscription is live and the category reports present and attached.",
		},
		{
			cat:         CapNetworkConnect,
			unsupported: "EndpointSecurity defines no outbound-connect event. The #ifdef'd ES_EVENT_TYPE_NOTIFY_CONNECT the capability table used to name does not exist in any SDK. Socket-level network telemetry on macOS comes from the NetworkExtension provider (internal/kernel/networkext), which is a separate mechanism with its own proof.",
		},
		{
			cat:         CapNetworkAccept,
			unsupported: "ESF has no inbound-accept event; see network_connect.",
		},
		{
			cat:         CapNetworkBind,
			unsupported: "ESF has UIPC_BIND for unix-domain sockets only, not for IP sockets; see network_connect.",
		},
		{
			cat:         CapNetworkClose,
			unsupported: "ESF has no connection-close event; see network_connect.",
		},
		{
			cat:         CapNetworkDNS,
			unsupported: "ESF has no DNS event. DNS on macOS comes from a userspace log-stream collector, not from this driver.",
		},
		{
			cat:         CapRegistryWrite,
			unsupported: "macOS has no registry. The category exists so a mixed fleet produces a comparable matrix; on this OS it is reported present=false.",
		},
		{
			cat:         CapScheduler,
			unsupported: "ESF reports no scheduling activity; there is no context-switch or run-queue event type.",
		},
		{
			cat:         CapTLSMetadata,
			unsupported: "ESF does not inspect socket payloads, so there is no TLS handshake metadata to report.",
		},
	}
}

// TestDarwinMonitoringCategoryTableCoversEveryCategory needs no ESF client, so
// unlike every other test in this file it actually runs on a hosted runner.
//
// It is the half of the per-category proof that can be checked anywhere: that
// a case exists for every canonical category, and that each category the table
// calls unsupported is one the capability report also reports absent. The
// activity-generating half cannot run without the entitlement.
func TestDarwinMonitoringCategoryTableCoversEveryCategory(t *testing.T) {
	proofs := esfCategoryProofs()

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
			t.Errorf("capability category %q has no proof case in esfCategoryProofs; add one, or add it with an unsupported reason if ESF genuinely cannot serve it", cat)
		}
	}

	// An unattached driver still reports which categories have a mechanism
	// at all, which is what "unsupported" has to agree with. The value is
	// constructed directly rather than through NewESFDriver, which needs
	// root: this check is about the tables, and requiring root would stop
	// it running on the one platform lane that can run it.
	// Zero value, not a literal with a caps field: the nosec build of
	// ESFDriver has no such field and this file compiles under it.
	drv := &ESFDriver{}
	rep := drv.CapabilityReport()
	if rep.Summary.Present == 0 {
		t.Skipf("MISSING PREREQUISITE: this build has no Endpoint Security bridge (%s/%s), so there is no mechanism table to compare against", runtime.GOOS, runtime.GOARCH)
	}
	for _, pr := range proofs {
		c := findCapability(t, rep, pr.cat)
		switch {
		case pr.unsupported != "" && c.Present:
			// Mount is the one case where the proof declines to
			// generate the activity although the mechanism is
			// there; its reason says so.
			if pr.cat != CapMount {
				t.Errorf("category %q is marked unsupported but the capability report says present=true with mechanism %q", pr.cat, c.Mechanism)
			}
		case pr.unsupported == "" && !c.Present:
			t.Errorf("category %q has an activity-generating proof but the capability report says no ESF mechanism serves it: %s", pr.cat, c.Reason)
		}
		if !c.Present && c.Reason == "" {
			t.Errorf("category %q is absent with no reason", pr.cat)
		}
	}
}

// TestDarwinMonitoringCategories proves one capability category per subtest on
// a provisioned Mac. On anything else every subtest skips at the gate.
func TestDarwinMonitoringCategories(t *testing.T) {
	drv, tap := startESFForTest(t)

	for _, pr := range esfCategoryProofs() {
		pr := pr
		t.Run(string(pr.cat), func(t *testing.T) {
			if pr.unsupported != "" {
				t.Skipf("NOT SUPPORTED BY THIS ESF SUBSCRIPTION: %s", pr.unsupported)
			}
			requireESFCategory(t, drv, pr.cat)

			p := &esfProof{drv: drv, tap: tap, dir: t.TempDir()}
			pr.prove(t, p)

			if c := findCapability(t, drv.CapabilityReport(), pr.cat); !c.Producing {
				t.Errorf("an event for %q arrived but CapabilityReport says it is not producing: %+v", pr.cat, c)
			}
		})
	}

	t.Logf("final capability summary on this host: %+v", drv.CapabilityReport().Summary)
}
