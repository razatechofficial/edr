package collector

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CommandRunner runs bounded shell commands for log_targets (command / full_command).
type CommandRunner struct {
	shell string
	args  []string

	mu            sync.Mutex
	lastRun       time.Time
	cooldown      time.Duration
	ratePerMinute int
	windowStart   time.Time
	windowCount   int
}

// NewCommandRunner builds a runner. command uses sh -c / cmd /c; fullCommand runs path as argv0 when needed.
func NewCommandRunner(kind, path string) *CommandRunner {
	path = strings.TrimSpace(path)
	if path == "" {
		return &CommandRunner{cooldown: time.Minute}
	}
	win := runtime.GOOS == "windows"
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "full_command":
		if win {
			return &CommandRunner{shell: "cmd", args: []string{"/C", path}, cooldown: 5 * time.Second, ratePerMinute: 6}
		}
		return &CommandRunner{shell: "/bin/sh", args: []string{"-c", path}, cooldown: 5 * time.Second, ratePerMinute: 6}
	default:
		if win {
			return &CommandRunner{shell: "cmd", args: []string{"/C", path}, cooldown: 5 * time.Second, ratePerMinute: 12}
		}
		return &CommandRunner{shell: "/bin/sh", args: []string{"-c", path}, cooldown: 5 * time.Second, ratePerMinute: 12}
	}
}

// SetPolicy applies per-target interval as cooldown floor and caps bursts.
func (r *CommandRunner) SetPolicy(interval time.Duration, perMin int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if interval > 0 {
		r.cooldown = interval
	}
	if perMin > 0 {
		r.ratePerMinute = perMin
	}
}

// Run executes the command when rate limits allow.
func (r *CommandRunner) Run(ctx context.Context) ([]byte, error) {
	if r == nil || r.shell == "" {
		return nil, nil
	}
	r.mu.Lock()
	now := time.Now()
	if d := r.cooldown; d > 0 && !r.lastRun.IsZero() && now.Sub(r.lastRun) < d {
		r.mu.Unlock()
		return nil, nil
	}
	if r.ratePerMinute > 0 {
		if now.Sub(r.windowStart) > time.Minute {
			r.windowStart = now
			r.windowCount = 0
		}
		if r.windowCount >= r.ratePerMinute {
			r.mu.Unlock()
			return nil, nil
		}
		r.windowCount++
	}
	r.lastRun = now
	sh := r.shell
	args := r.args
	r.mu.Unlock()

	c := exec.CommandContext(ctx, sh, args...)
	return c.CombinedOutput()
}
