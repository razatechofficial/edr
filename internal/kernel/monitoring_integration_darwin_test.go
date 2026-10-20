//go:build darwin && integration

package kernel

// macOS end-to-end monitoring proof.
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
// Run on a provisioned host with:
//
//	sudo -E go test -tags=integration ./internal/kernel/ -run TestDarwinMonitoring -v

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	darwinHelperEnvVar = "EDR_MONITORING_ITEST_HELPER"
	darwinHelperArgVar = "EDR_MONITORING_ITEST_ARG"
)

func init() {
	action := os.Getenv(darwinHelperEnvVar)
	if action == "" {
		return
	}
	arg := os.Getenv(darwinHelperArgVar)
	var err error
	switch action {
	case "exec":
		// Being executed is the event under test.
	case "write":
		err = os.WriteFile(arg, []byte("edr monitoring integration test\n"), 0o600)
	case "dial":
		var c net.Conn
		c, err = net.DialTimeout("tcp", arg, 5*time.Second)
		if err == nil {
			_, _ = c.Write([]byte("ping"))
			err = c.Close()
		}
	default:
		err = fmt.Errorf("unknown helper action %q", action)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper %s failed: %v\n", action, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func runDarwinHelper(t *testing.T, action, arg string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary for helper mode: %v", err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), darwinHelperEnvVar+"="+action, darwinHelperArgVar+"="+arg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper %s(%s) failed: %v\n%s", action, arg, err, out)
	}
}

// startESFForTest applies the environment gates and returns a started driver.
// It skips, never fails.
func startESFForTest(t *testing.T) (*ESFDriver, *RingBuffer) {
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

	buf := NewRingBuffer(1 << 20)
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
	return drv, buf
}

// esfEvent is one decoded JSON envelope from the ESF driver.
type esfEvent struct {
	Type  string `json:"type"`
	ESFOp string `json:"esf_op"`
	PID   int    `json:"pid"`
	Path  string `json:"path"`
	Comm  string `json:"comm"`
}

func collectESFEvents(t *testing.T, buf *RingBuffer, timeout time.Duration, match func(esfEvent) bool) (esfEvent, int, bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	count := 0
	for time.Now().Before(deadline) {
		data, err := buf.TryRead()
		if err != nil || data == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		var ev esfEvent
		if json.Unmarshal(data, &ev) != nil {
			continue
		}
		count++
		if match(ev) {
			return ev, count, true
		}
	}
	return esfEvent{}, count, false
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

// TestDarwinMonitoringProcessExec execs a child and asserts the ESF exec
// event surfaces.
func TestDarwinMonitoringProcessExec(t *testing.T) {
	drv, buf := startESFForTest(t)
	requireESFCategory(t, drv, CapProcessExec)

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary: %v", err)
	}
	wantName := filepath.Base(self)

	runDarwinHelper(t, "exec", "")

	ev, seen, ok := collectESFEvents(t, buf, 10*time.Second, func(e esfEvent) bool {
		return e.Type == "process" && strings.Contains(e.Path, wantName)
	})
	if !ok {
		t.Fatalf("no ESF exec event for %q arrived within 10s (%d events seen)", wantName, seen)
	}
	t.Logf("exec event: pid=%d op=%s path=%q", ev.PID, ev.ESFOp, ev.Path)

	if c := findCapability(t, drv.CapabilityReport(), CapProcessExec); !c.Producing {
		t.Errorf("an exec event arrived but CapabilityReport says process_exec is not producing: %+v", c)
	}
}

// TestDarwinMonitoringFileWrite writes a file in a child process and asserts a
// file event naming it surfaces.
func TestDarwinMonitoringFileWrite(t *testing.T) {
	drv, buf := startESFForTest(t)
	requireESFCategory(t, drv, CapFileWrite)

	path := filepath.Join(t.TempDir(), "edr-monitoring-itest.txt")
	runDarwinHelper(t, "write", path)

	base := filepath.Base(path)
	ev, seen, ok := collectESFEvents(t, buf, 10*time.Second, func(e esfEvent) bool {
		return e.Type == "file" && strings.Contains(e.Path, base)
	})
	if !ok {
		t.Fatalf("no ESF file event naming %q arrived within 10s (%d events seen)", base, seen)
	}
	t.Logf("file event: pid=%d op=%s path=%q", ev.PID, ev.ESFOp, ev.Path)
}

// TestDarwinMonitoringOutboundTCPConnect dials a local listener from a child
// process.
//
// NOTIFY_CONNECT is #ifdef-guarded in esf_subscribe_all, so on an older build
// SDK this category is absent and the test skips rather than failing for a
// reason the agent cannot control.
func TestDarwinMonitoringOutboundTCPConnect(t *testing.T) {
	drv, buf := startESFForTest(t)
	requireESFCategory(t, drv, CapNetworkConnect)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("MISSING PREREQUISITE: cannot bind a loopback TCP listener: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()

	runDarwinHelper(t, "dial", ln.Addr().String())

	_, seen, ok := collectESFEvents(t, buf, 10*time.Second, func(e esfEvent) bool {
		return e.Type == "network"
	})
	if !ok {
		t.Fatalf("no ESF network event arrived within 10s after an outbound TCP connect to %s (%d events seen)", ln.Addr(), seen)
	}

	if c := findCapability(t, drv.CapabilityReport(), CapNetworkConnect); !c.Producing {
		t.Errorf("a network event arrived but CapabilityReport says network_connect is not producing: %+v", c)
	}
}
