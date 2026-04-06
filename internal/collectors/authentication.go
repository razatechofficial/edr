package collectors

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// AuthenticationEvent is emitted when a user authentication attempt is detected,
// either from kernel events or platform-specific log sources.
type AuthenticationEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	User      string    `json:"user"`
	AuthType  string    `json:"auth_type"`
	Outcome   string    `json:"outcome"`
	SourceIP  string    `json:"source_ip,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
}

// AuthenticationCollector handles authentication events from both kernel
// ring buffer events and platform-specific log sources (auth.log, journald,
// macOS unified log).
type AuthenticationCollector struct {
	logger *zap.Logger
	out    chan<- interface{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewAuthenticationCollector creates an AuthenticationCollector with the given logger.
func NewAuthenticationCollector(logger *zap.Logger) *AuthenticationCollector {
	return &AuthenticationCollector{logger: logger}
}

// Name returns the collector identifier.
func (c *AuthenticationCollector) Name() string { return "authentication" }

// EventTypes returns the coarse event types this collector subscribes to.
func (c *AuthenticationCollector) EventTypes() []events.EventType {
	return []events.EventType{events.EventAuth}
}

// Start stores the output channel and begins platform log monitoring.
func (c *AuthenticationCollector) Start(ctx context.Context, _ *kernel.RingBuffer, out chan<- interface{}) error {
	c.out = out
	ctx, c.cancel = context.WithCancel(ctx)
	c.wg.Add(1)
	go c.monitorPlatformLogs(ctx)
	return nil
}

// Stop cancels the platform log monitor and waits for it to exit.
func (c *AuthenticationCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	return nil
}

func (c *AuthenticationCollector) processRaw(evt *RawEvent) {
	if evt.Type != EventAuthentication {
		return
	}

	r := newPayloadReader(evt.Payload)
	authType := r.Uint8()
	outcome := r.Uint8()
	userName := r.String()
	sourceIP := r.String()
	sessionID := r.String()
	if r.Err() != nil {
		c.logger.Warn("malformed authentication payload", zap.Error(r.Err()))
		return
	}

	c.emit(&AuthenticationEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		User:      userName,
		AuthType:  authTypeName(authType),
		Outcome:   authOutcomeName(outcome),
		SourceIP:  sourceIP,
		SessionID: sessionID,
	})
}

func (c *AuthenticationCollector) monitorPlatformLogs(ctx context.Context) {
	defer c.wg.Done()

	switch runtime.GOOS {
	case "linux":
		c.monitorLinuxAuth(ctx)
	case "darwin":
		c.monitorDarwinAuth(ctx)
	default:
		c.logger.Info("no platform auth log source available",
			zap.String("os", runtime.GOOS))
	}
}

func (c *AuthenticationCollector) monitorLinuxAuth(ctx context.Context) {
	f, err := os.Open("/var/log/auth.log")
	if err != nil {
		c.logger.Warn("cannot open auth.log, falling back to journald", zap.Error(err))
		c.monitorJournald(ctx)
		return
	}
	defer f.Close()

	// Seek to end so we only process new entries.
	if _, err := f.Seek(0, 2); err != nil {
		c.logger.Warn("failed to seek to end of auth.log", zap.Error(err))
		return
	}

	reader := bufio.NewReader(f)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				line, err := reader.ReadString('\n')
				if len(line) > 0 {
					c.parseAuthLogLine(strings.TrimRight(line, "\n"))
				}
				if err != nil {
					break
				}
			}
		}
	}
}

func (c *AuthenticationCollector) monitorJournald(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "journalctl", "-f",
		"-u", "ssh", "-u", "sshd",
		"--output=short", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.logger.Error("failed to pipe journalctl stdout", zap.Error(err))
		return
	}
	if err := cmd.Start(); err != nil {
		c.logger.Error("failed to start journalctl", zap.Error(err))
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		c.parseAuthLogLine(scanner.Text())
	}
	_ = cmd.Wait()
}

func (c *AuthenticationCollector) monitorDarwinAuth(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "log", "stream",
		"--predicate", `eventMessage contains "authentication" || eventMessage contains "login"`,
		"--style", "ndjson")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.logger.Error("failed to pipe log stream stdout", zap.Error(err))
		return
	}
	if err := cmd.Start(); err != nil {
		c.logger.Error("failed to start log stream", zap.Error(err))
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "authentication") || strings.Contains(line, "login") {
			c.emit(&AuthenticationEvent{
				Timestamp: time.Now().UTC(),
				AuthType:  "system",
				Outcome:   "unknown",
				User:      extractField(line, "user"),
				SourceIP:  extractField(line, "from"),
			})
		}
	}
	_ = cmd.Wait()
}

func (c *AuthenticationCollector) parseAuthLogLine(line string) {
	now := time.Now().UTC()

	switch {
	case strings.Contains(line, "Accepted"):
		c.emit(&AuthenticationEvent{
			Timestamp: now,
			AuthType:  extractAuthMethod(line),
			Outcome:   "success",
			User:      extractField(line, "for"),
			SourceIP:  extractField(line, "from"),
		})
	case strings.Contains(line, "Failed"):
		c.emit(&AuthenticationEvent{
			Timestamp: now,
			AuthType:  extractAuthMethod(line),
			Outcome:   "failure",
			User:      extractField(line, "for"),
			SourceIP:  extractField(line, "from"),
		})
	case strings.Contains(line, "session opened"):
		c.emit(&AuthenticationEvent{
			Timestamp: now,
			AuthType:  "session",
			Outcome:   "success",
			User:      extractField(line, "user"),
		})
	}
}

func (c *AuthenticationCollector) emit(evt interface{}) {
	select {
	case c.out <- evt:
	default:
		c.logger.Warn("output channel full, dropping auth event")
	}
}

func extractField(line, prefix string) string {
	idx := strings.Index(line, prefix+" ")
	if idx == -1 {
		return ""
	}
	rest := line[idx+len(prefix)+1:]
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func extractAuthMethod(line string) string {
	for _, method := range []string{"publickey", "password", "keyboard-interactive", "gssapi-with-mic"} {
		if strings.Contains(line, method) {
			return method
		}
	}
	return "unknown"
}

func authTypeName(t uint8) string {
	switch t {
	case 0:
		return "password"
	case 1:
		return "publickey"
	case 2:
		return "kerberos"
	case 3:
		return "certificate"
	case 4:
		return "mfa"
	default:
		return "unknown"
	}
}

func authOutcomeName(o uint8) string {
	switch o {
	case 0:
		return "success"
	case 1:
		return "failure"
	case 2:
		return "error"
	default:
		return "unknown"
	}
}
