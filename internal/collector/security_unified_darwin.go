//go:build darwin

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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// darwinSecurityLogSubsystems are unified-log sources referenced by imported macOS Sigma UL rules.
var darwinSecurityLogSubsystems = []string{
	"com.apple.sudo",
	"com.apple.TCC",
	"com.apple.xpc",
	"com.apple.syspolicy",
	"com.apple.launchd",
	"com.apple.ManagedClient",
	"com.apple.securityd",
	"com.apple.security.assessment",
	"com.apple.authorization",
	"com.apple.alf",
	"com.apple.network",
	"com.apple.loginwindow",
	"com.apple.opendirectoryd",
}

// DarwinSecurityLogSource tails unified logging for security-relevant subsystems
// and emits AuthEvent rows for Sigma UL rule matching (subsystem + message).
type DarwinSecurityLogSource struct {
	endpointID string
	hostname   string

	mu      sync.Mutex
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	started bool

	emitted atomic.Uint64
	errs    atomic.Pointer[string]
}

func NewDarwinSecurityLogSource(endpointID, hostname string) *DarwinSecurityLogSource {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	return &DarwinSecurityLogSource{
		endpointID: endpointID,
		hostname:   hostname,
	}
}

func darwinSecurityLogPredicate() string {
	parts := make([]string, 0, len(darwinSecurityLogSubsystems))
	for _, sub := range darwinSecurityLogSubsystems {
		parts = append(parts, fmt.Sprintf(`subsystem == %q`, sub))
	}
	return strings.Join(parts, " OR ")
}

func (s *DarwinSecurityLogSource) Run(ctx context.Context, sink *StreamingSink) error {
	cmd := exec.CommandContext(ctx, "log", "stream",
		"--style", "ndjson",
		"--predicate", darwinSecurityLogPredicate(),
		"--info",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.recordError(err)
		return fmt.Errorf("security log stream stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		s.recordError(err)
		return fmt.Errorf("security log stream start: %w", err)
	}
	s.mu.Lock()
	s.cmd = cmd
	s.stdout = stdout
	s.started = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.started = false
		s.mu.Unlock()
		_ = stdout.Close()
		_ = cmd.Wait()
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.dispatchLine(ctx, scanner.Bytes(), sink)
	}
	if err := scanner.Err(); err != nil {
		s.recordError(err)
		return err
	}
	return nil
}

func (s *DarwinSecurityLogSource) dispatchLine(ctx context.Context, line []byte, sink *StreamingSink) {
	ev, ok := parseDarwinSecurityLogLine(line, s.endpointID, s.hostname)
	if !ok {
		return
	}
	if sink.Send(ctx, Telemetry{Auth: &ev}) {
		s.emitted.Add(1)
	}
}

func parseDarwinSecurityLogLine(line []byte, endpointID, hostname string) (schema.AuthEvent, bool) {
	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		return schema.AuthEvent{}, false
	}
	subsystem, _ := entry["subsystem"].(string)
	message, _ := entry["eventMessage"].(string)
	if subsystem == "" || strings.TrimSpace(message) == "" {
		return schema.AuthEvent{}, false
	}
	category, _ := entry["category"].(string)
	authType := darwinSecurityAuthType(subsystem, category, message)
	now := time.Now().UTC()
	return schema.AuthEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventAuth,
			EndpointID:    endpointID,
			Timestamp:     now,
			Hostname:      hostname,
			OS:            runtime.GOOS,
		},
		AuthType:  authType,
		Outcome:   "log",
		Message:   message,
		Subsystem: subsystem,
		Category:  category,
	}, true
}

func darwinSecurityAuthType(subsystem, category, message string) string {
	switch subsystem {
	case "com.apple.sudo":
		return "sudo"
	case "com.apple.TCC":
		return "tcc"
	case "com.apple.xpc":
		return "xpc"
	case "com.apple.security.assessment":
		return "gatekeeper"
	case "com.apple.securityd":
		return "securityd"
	case "com.apple.alf":
		return "firewall"
	case "com.apple.launchd":
		return "launchd"
	case "com.apple.ManagedClient":
		return "mdm"
	default:
		if category != "" {
			return category
		}
		if strings.Contains(strings.ToLower(message), "sudo") {
			return "sudo"
		}
		return "security_log"
	}
}

func (s *DarwinSecurityLogSource) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "security_unified_log",
		OS:     "darwin",
		Source: "log-stream-security",
		Status: "healthy",
		EPSOut: s.emitted.Load(),
	}
	s.mu.Lock()
	st := s.started
	s.mu.Unlock()
	if !st {
		src.Status = "unavailable"
	}
	if errPtr := s.errs.Load(); errPtr != nil && *errPtr != "" {
		src.LastError = *errPtr
		src.Status = "degraded"
	}
	return src.ToMap()
}

func (s *DarwinSecurityLogSource) recordError(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	s.errs.Store(&msg)
}
