package collector

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// AuthCollector monitors authentication events by tailing platform-specific
// auth logs. On Linux it reads /var/log/auth.log (or /var/log/secure), on
// macOS it reads /var/log/system.log, and on Windows it is a placeholder
// for ETW Security event log integration.
type AuthCollector struct {
	endpointID string
	hostname   string
	dataDir    string
	logPath    string
	lastOffset int64

	mu     sync.Mutex
	events []schema.AuthEvent
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

func (ac *AuthCollector) Name() string { return "auth" }

func (ac *AuthCollector) Collect(_ context.Context) ([]Telemetry, error) {
	if runtime.GOOS == "windows" {
		return authWindowsSecurityTelemetry(ac)
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
	return out, nil
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
		User:     strings.TrimSpace(user),
		AuthType: authType,
		SourceIP: strings.TrimSpace(sourceIP),
		Outcome:  outcome,
	}, true
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
