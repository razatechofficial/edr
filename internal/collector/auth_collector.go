package collector

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// AuthCollector monitors authentication events by tailing platform-specific
// auth logs. On Linux it reads /var/log/auth.log (or /var/log/secure), on
// macOS it reads /var/log/system.log when present, and on Windows it queries
// the Security event log via the Windows Event API (evtsubscribe path in Collect).
//
// P2-14: the Windows-only EVT_HANDLE state used to live in a
// package-global map keyed by *AuthCollector. We now embed an opaque
// any-typed pointer (winState) so the per-collector lifetime is
// explicit and the global map can be retired. Non-Windows builds
// ignore winState.
type AuthCollector struct {
	endpointID string
	hostname   string
	dataDir    string
	logPath    string
	lastOffset int64

	mu     sync.Mutex
	events []schema.AuthEvent

	scans   atomic.Uint64
	emitted atomic.Uint64

	// winState holds *winAuthState on Windows; nil and unused elsewhere.
	winStateMu sync.Mutex
	winState   any
}

func NewAuthCollector(endpointID, dataDir string) *AuthCollector {
	hostname, _ := os.Hostname()
	logPath := detectAuthLogPath()
	return &AuthCollector{
		endpointID: endpointID,
		hostname:   hostname,
		dataDir:    dataDir,
		logPath:    logPath,
	}
}

// NewAuthCollectorWithLogPath constructs an auth collector that tails the given
// log path (used on rare GOOS when standard detection returns "").
func NewAuthCollectorWithLogPath(endpointID, dataDir, logPath string) *AuthCollector {
	hostname, _ := os.Hostname()
	return &AuthCollector{
		endpointID: endpointID,
		hostname:   hostname,
		dataDir:    dataDir,
		logPath:    logPath,
	}
}

func (ac *AuthCollector) Name() string { return "auth" }

// Stop releases platform-specific resources held by the collector. On
// Windows it closes the EvtSubscribe/EvtQuery and bookmark handles that
// would otherwise leak across collector lifecycle (EVT_HANDLE leak,
// P1-12). On all other platforms Stop is a no-op — file-tail readers
// have no long-lived OS resources.
func (ac *AuthCollector) Stop() {
	if runtime.GOOS == "windows" {
		authWindowsStop(ac)
	}
}

func (ac *AuthCollector) Collect(_ context.Context) ([]Telemetry, error) {
	ac.scans.Add(1)
	if runtime.GOOS == "windows" {
		out, err := authWindowsSecurityTelemetry(ac)
		if err == nil {
			ac.emitted.Add(uint64(len(out)))
		}
		return out, err
	}
	if ac.logPath == "" {
		return nil, nil
	}

	newEvents := ac.readNewLines()

	ac.mu.Lock()
	all := append(ac.events, newEvents...)
	ac.events = nil
	ac.mu.Unlock()

	out := make([]Telemetry, 0, len(all))
	for i := range all {
		out = append(out, Telemetry{Auth: &all[i]})
	}
	ac.emitted.Add(uint64(len(out)))
	return out, nil
}

// ExportMonitoringHealth surfaces auth-log tailing stats.
func (ac *AuthCollector) ExportMonitoringHealth() map[string]any {
	src := MonitoringSource{
		Name:   "auth",
		OS:     runtime.GOOS,
		Source: "syslog_tail",
		Status: "healthy",
		EPSIn:  ac.scans.Load(),
		EPSOut: ac.emitted.Load(),
	}
	switch {
	case runtime.GOOS == "windows":
		src.Source = "evtsubscribe"
	case ac.logPath == "":
		src.Status = "unavailable"
		src.LastError = authLogPathEmptyHealthMessage()
	}
	return src.ToMap()
}

func (ac *AuthCollector) readNewLines() []schema.AuthEvent {
	f, err := os.Open(ac.logPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil
	}

	if info.Size() < ac.lastOffset {
		ac.lastOffset = 0
	}

	if _, err := f.Seek(ac.lastOffset, 0); err != nil {
		return nil
	}

	var events []schema.AuthEvent
	scanner := bufio.NewScanner(f)
	now := time.Now().UTC()

	for scanner.Scan() {
		line := scanner.Text()
		if ev, ok := parseAuthLine(line, ac.endpointID, ac.hostname, now); ok {
			events = append(events, ev)
		}
	}

	pos, _ := f.Seek(0, 1)
	ac.lastOffset = pos
	return events
}

func parseAuthLine(line, endpointID, hostname string, ts time.Time) (schema.AuthEvent, bool) {
	lower := strings.ToLower(line)

	var user, authType, sourceIP, outcome string

	switch {
	case strings.Contains(lower, "accepted password") || strings.Contains(lower, "accepted publickey"):
		authType = "ssh"
		outcome = "success"
		user = extractField(line, "for ")
		sourceIP = extractField(line, "from ")
	case strings.Contains(lower, "failed password"):
		authType = "ssh"
		outcome = "failure"
		user = extractField(line, "for ")
		sourceIP = extractField(line, "from ")
	case strings.Contains(lower, "session opened"):
		authType = "session"
		outcome = "success"
		user = extractField(line, "for user ")
	case strings.Contains(lower, "session closed"):
		authType = "session"
		outcome = "closed"
		user = extractField(line, "for user ")
	case strings.Contains(lower, "authentication failure"):
		authType = "pam"
		outcome = "failure"
		user = extractField(line, "user=")
	case strings.Contains(lower, "sudo:"):
		authType = "sudo"
		if strings.Contains(lower, "not allowed") || strings.Contains(lower, "incorrect password") {
			outcome = "failure"
		} else {
			outcome = "success"
		}
		user = extractSudoUser(line)
	default:
		return schema.AuthEvent{}, false
	}

	if user == "" {
		return schema.AuthEvent{}, false
	}

	return schema.AuthEvent{
		BaseEvent: schema.BaseEvent{
			SchemaVersion: schema.SchemaVersionV1,
			EventType:     schema.EventAuth,
			EndpointID:    endpointID,
			Timestamp:     ts,
			Hostname:      hostname,
			OS:            runtime.GOOS,
		},
		User:      strings.TrimSpace(user),
		AuthType:  authType,
		SourceIP:  strings.TrimSpace(sourceIP),
		Outcome:   outcome,
		Message:   line,
		Subsystem: authSubsystemForLine(authType, lower),
	}, true
}

func authSubsystemForLine(authType, lower string) string {
	switch authType {
	case "sudo":
		return "com.apple.sudo"
	case "ssh":
		return "com.apple.ssh"
	case "session":
		if strings.Contains(lower, "sudo") {
			return "com.apple.sudo"
		}
		return "com.apple.loginwindow"
	case "pam":
		return "com.apple.opendirectoryd"
	default:
		return ""
	}
}

func extractField(line, prefix string) string {
	idx := strings.Index(strings.ToLower(line), strings.ToLower(prefix))
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(prefix):]
	end := strings.IndexAny(rest, " \t\n,;)")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func extractSudoUser(line string) string {
	idx := strings.Index(line, "sudo:")
	if idx < 0 {
		return ""
	}
	before := strings.TrimSpace(line[:idx])
	parts := strings.Fields(before)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func detectAuthLogPath() string {
	switch runtime.GOOS {
	case "linux":
		for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return ""
	case "darwin":
		return "/var/log/system.log"
	default:
		return ""
	}
}
