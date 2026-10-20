//go:build windows && integration

package kernel

// Windows end-to-end monitoring proof.
//
// These drive the ETW driver, which is the part of Windows kernel telemetry
// that needs only elevation. Starting a NT Kernel Logger-class realtime
// session requires SeSystemProfilePrivilege, which an elevated session holds;
// GitHub-hosted windows runners do run elevated, so unlike the macOS tests
// these can actually execute in CI.
//
// What these do NOT cover is the signed-driver tier: the WDM/minifilter paths
// (wdm_ioctl_windows.go, minifilter_ctl_windows.go) need a kernel-mode driver
// signed with an EV certificate and cross-signed by Microsoft, which no CI
// runner can load. Those categories are reported absent by the capability
// report rather than tested here.
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
	"strings"
	"testing"
	"time"
)

const (
	winHelperEnvVar = "EDR_MONITORING_ITEST_HELPER"
	winHelperArgVar = "EDR_MONITORING_ITEST_ARG"
)

func init() {
	action := os.Getenv(winHelperEnvVar)
	if action == "" {
		return
	}
	arg := os.Getenv(winHelperArgVar)
	var err error
	switch action {
	case "exec":
		// Being executed is the event under test.
	case "write":
		err = os.WriteFile(arg, []byte("edr monitoring integration test\r\n"), 0o600)
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

func runWindowsHelper(t *testing.T, action, arg string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary for helper mode: %v", err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), winHelperEnvVar+"="+action, winHelperArgVar+"="+arg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper %s(%s) failed: %v\n%s", action, arg, err, out)
	}
}

// startETWForTest applies the environment gates and returns a started driver.
// It skips, never fails.
func startETWForTest(t *testing.T) (*ETWDriver, *RingBuffer) {
	t.Helper()

	drv, err := NewETWDriver("monitoring-integration-test")
	if err != nil {
		t.Skipf("MISSING PREREQUISITE: ETW driver could not be constructed: %v", err)
	}

	buf := NewRingBuffer(1 << 20)
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
	// is per-provider, so report it and let each subtest gate on the
	// provider it needs.
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
	return drv, buf
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

// etwEvent is one decoded JSON envelope from the ETW driver.
type etwEvent struct {
	Type      string `json:"type"`
	PID       uint32 `json:"pid"`
	EventID   uint16 `json:"event_id"`
	ImageName string `json:"image_name"`
	Cmdline   string `json:"cmdline"`
	FileName  string `json:"file_name"`
	Path      string `json:"path"`
}

func collectETWEvents(t *testing.T, buf *RingBuffer, timeout time.Duration, match func(etwEvent) bool) (etwEvent, int, bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	count := 0
	for time.Now().Before(deadline) {
		data, err := buf.TryRead()
		if err != nil || data == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		var ev etwEvent
		if json.Unmarshal(data, &ev) != nil {
			continue
		}
		count++
		if match(ev) {
			return ev, count, true
		}
	}
	return etwEvent{}, count, false
}

// TestWindowsMonitoringProcessExec starts a child process and asserts the ETW
// ProcessStart event surfaces.
func TestWindowsMonitoringProcessExec(t *testing.T) {
	drv, buf := startETWForTest(t)
	requireETWCategory(t, drv, CapProcessExec)

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary: %v", err)
	}
	wantName := strings.ToLower(filepath.Base(self))

	runWindowsHelper(t, "exec", "")

	ev, seen, ok := collectETWEvents(t, buf, 15*time.Second, func(e etwEvent) bool {
		if e.Type != "process" {
			return false
		}
		hay := strings.ToLower(e.ImageName + " " + e.Cmdline)
		return strings.Contains(hay, wantName)
	})
	if !ok {
		t.Fatalf("no ETW ProcessStart event for %q arrived within 15s (%d events seen)", wantName, seen)
	}
	t.Logf("process event: pid=%d event_id=%d image=%q", ev.PID, ev.EventID, ev.ImageName)

	if c := findCapability(t, drv.CapabilityReport(), CapProcessExec); !c.Producing {
		t.Errorf("a ProcessStart event arrived but CapabilityReport says process_exec is not producing: %+v", c)
	}
}

// TestWindowsMonitoringFileWrite writes a file in a child process and asserts
// a Kernel-File event naming it surfaces.
func TestWindowsMonitoringFileWrite(t *testing.T) {
	drv, buf := startETWForTest(t)
	requireETWCategory(t, drv, CapFileWrite)

	path := filepath.Join(t.TempDir(), "edr-monitoring-itest.txt")
	runWindowsHelper(t, "write", path)

	base := strings.ToLower(filepath.Base(path))
	ev, seen, ok := collectETWEvents(t, buf, 15*time.Second, func(e etwEvent) bool {
		if e.Type != "file" {
			return false
		}
		return strings.Contains(strings.ToLower(e.FileName+" "+e.Path), base)
	})
	if !ok {
		// Kernel-File on some builds reports only a FileObject handle
		// and resolves the path from a cache, so a miss here is a real
		// gap in path attribution rather than an absent prerequisite.
		t.Fatalf("no ETW file event naming %q arrived within 15s (%d events seen); check KernelFileObjectCache path resolution", base, seen)
	}
	t.Logf("file event: pid=%d event_id=%d name=%q", ev.PID, ev.EventID, ev.FileName+ev.Path)
}

// TestWindowsMonitoringOutboundTCPConnect dials a local listener from a child
// process and asserts the Kernel-Network connect event surfaces.
func TestWindowsMonitoringOutboundTCPConnect(t *testing.T) {
	drv, buf := startETWForTest(t)
	requireETWCategory(t, drv, CapNetworkConnect)

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

	runWindowsHelper(t, "dial", ln.Addr().String())

	_, seen, ok := collectETWEvents(t, buf, 15*time.Second, func(e etwEvent) bool {
		return e.Type == "network"
	})
	if !ok {
		t.Fatalf("no ETW network event arrived within 15s after an outbound TCP connect to %s (%d events seen)", ln.Addr(), seen)
	}

	if c := findCapability(t, drv.CapabilityReport(), CapNetworkConnect); !c.Producing {
		t.Errorf("a network event arrived but CapabilityReport says network_connect is not producing: %+v", c)
	}
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
		if !c.Attached {
			continue
		}
		for _, hook := range c.Attachments {
			if !activeProviders[hook] {
				t.Errorf("category %q reports attachment %q, but that provider is not active in ProviderHealthSnapshot", c.Category, hook)
			}
		}
	}
	t.Logf("capability summary on this host: %+v", rep.Summary)
}
