package collector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// ProcessCollector emits ProcessEvent telemetry. On Linux it uses the /proc
// diff source so only newly visible pids are emitted, eliminating the
// per-cycle `ps -axo` fork that previously dominated CPU usage. macOS and
// Windows use native platform sources. Other Unix-like systems use a bounded
// `ps` fallback (see process_collector_other.go).
type ProcessCollector struct {
	EndpointID string
	Hostname   string

	mu      sync.Mutex // guards: tracker, linuxImpl
	tracker *LineageTracker
	// linuxImpl is *ProcSource on Linux; left nil elsewhere. Storing it as any
	// avoids a type-name dependency on a build-tagged symbol.
	linuxImpl any

	scans   atomic.Uint64
	emitted atomic.Uint64
	errs    atomic.Pointer[string]
}

func NewProcessCollector(endpointID string) (*ProcessCollector, error) {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return &ProcessCollector{
		EndpointID: endpointID,
		Hostname:   host,
		tracker:    NewLineageTracker(0, 0),
	}, nil
}

// SetLineageTracker swaps in a shared tracker (typically owned by the agent).
func (c *ProcessCollector) SetLineageTracker(t *LineageTracker) {
	if t == nil {
		return
	}
	c.mu.Lock()
	c.tracker = t
	c.linuxImpl = nil // force re-init so ProcSource picks up the shared tracker
	c.mu.Unlock()
}

// LineageTracker exposes the underlying tracker for collectors that want to
// stamp events through the same identity store.
func (c *ProcessCollector) LineageTracker() *LineageTracker {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tracker
}

func (c *ProcessCollector) Name() string { return "process" }

// ExportMonitoringHealth surfaces ProcessCollector throughput.
func (c *ProcessCollector) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "process",
		OS:     runtime.GOOS,
		Source: "native_proc",
		Status: "healthy",
		EPSIn:  c.scans.Load(),
		EPSOut: c.emitted.Load(),
	}
	switch runtime.GOOS {
	case "linux":
		src.Source = "proc_diff"
	case "darwin":
		src.Source = "kern.proc.all"
	case "windows":
		src.Source = "toolhelp32"
	default:
		src.Source = "ps_fallback"
	}
	if errPtr := c.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (c *ProcessCollector) Collect(ctx context.Context) ([]Telemetry, error) {
	c.scans.Add(1)
	now := time.Now().UTC()
	user := os.Getenv("USER")
	out, err := c.collectNative(ctx, now, user)
	if err != nil {
		msg := err.Error()
		c.errs.Store(&msg)
	} else {
		c.emitted.Add(uint64(len(out)))
	}
	return out, err
}

func (c *ProcessCollector) collectFromPS(ctx context.Context, now time.Time, user string) ([]Telemetry, error) {
	cmd := exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=,args=")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ps collection failed: %w", err)
	}

	type procSnap struct {
		pid      int
		ppid     int
		cmdline  string
		procPath string
		name     string
	}
	snaps := make([]procSnap, 0, 128)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		pid, ppid, cmdline, ok := parsePSLine(sc.Text())
		if !ok {
			continue
		}
		procPath := firstArg(cmdline)
		snaps = append(snaps, procSnap{
			pid:      pid,
			ppid:     ppid,
			cmdline:  cmdline,
			procPath: procPath,
			name:     filepathBase(procPath),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(snaps) == 0 {
		return nil, fmt.Errorf("ps returned no parseable process rows")
	}

	nameByPID := make(map[int]string, len(snaps))
	for _, s := range snaps {
		nameByPID[s.pid] = s.name
	}
	telems := make([]Telemetry, 0, len(snaps))
	for _, s := range snaps {
		ev := schema.ProcessEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventProcess,
				EndpointID:    c.EndpointID,
				Timestamp:     now,
				Hostname:      c.Hostname,
				OS:            runtime.GOOS,
			},
			PID:         s.pid,
			PPID:        s.ppid,
			ParentName:  nameByPID[s.ppid],
			ProcessName: s.name,
			ProcessPath: s.procPath,
			CommandLine: s.cmdline,
			User:        user,
		}
		telems = append(telems, Telemetry{Process: &ev})
	}
	return telems, nil
}

func parsePSLine(line string) (pid int, ppid int, cmdline string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 3 {
		return 0, 0, "", false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, "", false
	}
	ppid, err = strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, "", false
	}
	cmdline = strings.Join(fields[2:], " ")
	return pid, ppid, cmdline, true
}

func filepathBase(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

func firstArg(cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return ""
	}
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
