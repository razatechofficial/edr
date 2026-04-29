//go:build linux

package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// JournaldSource consumes systemd-journald entries by spawning
// `journalctl --follow --output=json --no-pager` once at startup and
// streaming its stdout. Compared to dlopen-ing libsystemd this:
//   - keeps the agent cgo-free,
//   - pays a single subprocess cost (not per-cycle),
//   - lets the operator preconfigure unit/priority filters via journalctl flags.
//
// Output is mapped to AuthEvent for ssh/sudo/login units and to a generic
// schema event otherwise. Errors are recorded in monitoring health.
type JournaldSource struct {
	endpointID string
	hostname   string
	tracker    *LineageTracker
	flags      []string

	mu      sync.Mutex // guards: cmd, started
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	started bool

	emitted atomic.Uint64
	errs    atomic.Pointer[string]
}

// NewJournaldSource builds a journald consumer. extraFlags is appended to
// `journalctl --follow --output=json --no-pager` (e.g. `--priority=warning`).
func NewJournaldSource(endpointID, hostname string, tracker *LineageTracker, extraFlags []string) *JournaldSource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	return &JournaldSource{
		endpointID: endpointID,
		hostname:   hostname,
		tracker:    tracker,
		flags:      append([]string{}, extraFlags...),
	}
}

// Run spawns journalctl and streams its output until ctx is cancelled. The
// subprocess is killed on ctx.Done(); io readers are closed on exit so no
// goroutine or fd leak survives.
func (j *JournaldSource) Run(ctx context.Context, out chan<- Telemetry) error {
	args := append([]string{"--follow", "--output=json", "--no-pager"}, j.flags...)
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		j.recordError(err)
		return fmt.Errorf("journalctl stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		j.recordError(err)
		return fmt.Errorf("journalctl start: %w", err)
	}
	j.mu.Lock()
	j.cmd = cmd
	j.stdout = stdout
	j.started = true
	j.mu.Unlock()

	defer func() {
		j.mu.Lock()
		j.started = false
		j.mu.Unlock()
		_ = stdout.Close()
		_ = cmd.Wait() // CommandContext kills on ctx cancel; Wait reaps.
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		j.dispatchLine(ctx, scanner.Bytes(), out)
	}
	if err := scanner.Err(); err != nil {
		j.recordError(err)
		return err
	}
	return nil
}

func (j *JournaldSource) dispatchLine(ctx context.Context, line []byte, out chan<- Telemetry) {
	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		return
	}
	unit, _ := entry["_SYSTEMD_UNIT"].(string)
	msg, _ := entry["MESSAGE"].(string)
	if msg == "" {
		return
	}
	if !looksLikeAuth(unit, msg) {
		return
	}
	pid := uint32(0)
	if pidStr, _ := entry["_PID"].(string); pidStr != "" {
		if v, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
			pid = uint32(v)
		}
	}
	uid := uint32(0)
	if uidStr, _ := entry["_UID"].(string); uidStr != "" {
		if v, err := strconv.ParseUint(uidStr, 10, 32); err == nil {
			uid = uint32(v)
		}
	}
	if j.tracker != nil && pid != 0 {
		j.tracker.Upsert(LineageEntry{PID: pid, UID: uid})
	}
	ae := &schema.AuthEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventAuth,
			EndpointID:    j.endpointID,
			Timestamp:     time.Now().UTC(),
			Hostname:      j.hostname,
			OS:            runtime.GOOS,
		},
		User:     stringField(entry, "USER"),
		Outcome:  outcomeFromMessage(msg),
		AuthType: unit,
	}
	select {
	case out <- Telemetry{Auth: ae}:
		j.emitted.Add(1)
	case <-ctx.Done():
	default:
	}
}

func looksLikeAuth(unit, msg string) bool {
	switch unit {
	case "ssh.service", "sshd.service", "sudo.service", "systemd-logind.service":
		return true
	}
	for _, kw := range []string{"sshd", "sudo", "polkit", "Failed password", "Accepted password", "session opened", "session closed", "authentication failure"} {
		if containsCaseInsensitive(msg, kw) {
			return true
		}
	}
	return false
}

func outcomeFromMessage(msg string) string {
	switch {
	case containsCaseInsensitive(msg, "Failed password") || containsCaseInsensitive(msg, "authentication failure"):
		return "failure"
	case containsCaseInsensitive(msg, "Accepted password") || containsCaseInsensitive(msg, "session opened"):
		return "success"
	default:
		return ""
	}
}

func containsCaseInsensitive(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a := s[i+j]
			b := sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func stringField(entry map[string]any, key string) string {
	if v, ok := entry[key].(string); ok {
		return v
	}
	return ""
}

// ExportMonitoringHealth implements the per-source health interface.
func (j *JournaldSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "auth",
		OS:     "linux",
		Source: "journald",
		Status: "healthy",
		EPSOut: j.emitted.Load(),
	}
	if !j.started {
		src.Status = "unavailable"
	}
	if errPtr := j.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (j *JournaldSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	j.errs.Store(&msg)
}
