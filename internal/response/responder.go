package response

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/razatechofficial/edr/internal/schema"
	"go.uber.org/zap"
)

type Responder struct {
	allowKill bool
	protected protectedSet
}

// NewResponder builds a responder. The operator's protected list is added to
// the built-in floor rather than replacing it, so an empty list still leaves
// the critical processes of the platform untouchable.
func NewResponder(allowKill bool, protected []string) *Responder {
	return &Responder{allowKill: allowKill, protected: newProtectedSet(protected)}
}

func (r *Responder) Execute(cmd schema.ResponseCommand) schema.ResponseResult {
	switch cmd.Action {
	case schema.ResponseKillProcess:
		return r.killProcess(cmd)
	case schema.ResponseQuarantine:
		return quarantineFile(cmd)
	case schema.ResponseHostIsolate:
		return hostIsolate(cmd)
	default:
		return fail(cmd, "unsupported action")
	}
}

func (r *Responder) killProcess(cmd schema.ResponseCommand) schema.ResponseResult {
	if !r.allowKill {
		return fail(cmd, "kill action disabled by policy")
	}
	if cmd.ProcessPID <= 0 {
		return fail(cmd, "invalid process pid")
	}
	// pid 1 is init on every unix: terminating it panics the kernel. It is
	// checked before anything else because no name or path lookup is needed to
	// know the answer.
	if runtime.GOOS != "windows" && cmd.ProcessPID == 1 {
		return fail(cmd, "refusing to terminate pid 1")
	}

	// cmd.Reason is deliberately no longer consulted for the target's
	// identity. It is free text written by whatever produced the detection, so
	// treating it as a name meant an unrelated phrase could satisfy — or
	// silently fail — the protection check.
	if why, ok := r.protected.covers(cmd.ProcessName, cmd.FilePath); ok {
		return fail(cmd, "target process is protected: "+why)
	}

	// Self-protection covers the whole agent, not just this process. Killing
	// the service that supervises this one, or a sibling component, disables
	// the endpoint as surely as killing this pid would — and a detection
	// firing on the agent's own activity is exactly the case that produces it.
	if cmd.ProcessPID == os.Getpid() {
		return fail(cmd, "refusing self-termination")
	}
	if cmd.ProcessPID == os.Getppid() {
		return fail(cmd, "refusing to terminate the agent's parent process")
	}

	proc, err := os.FindProcess(cmd.ProcessPID)
	if err != nil {
		return fail(cmd, fmt.Sprintf("process lookup failed: %v", err))
	}
	if err := proc.Kill(); err != nil {
		return fail(cmd, fmt.Sprintf("kill failed: %v", err))
	}
	return ok(cmd, "process terminated")
}

func quarantineFile(cmd schema.ResponseCommand) schema.ResponseResult {
	if strings.TrimSpace(cmd.FilePath) == "" {
		return fail(cmd, "file path required")
	}
	qDir := ".quarantine"
	if err := os.MkdirAll(qDir, 0o750); err != nil {
		return fail(cmd, fmt.Sprintf("quarantine dir create failed: %v", err))
	}
	dst := filepath.Join(qDir, filepath.Base(cmd.FilePath))
	if err := os.Rename(cmd.FilePath, dst); err != nil {
		return fail(cmd, fmt.Sprintf("quarantine failed: %v", err))
	}
	return ok(cmd, "file quarantined")
}

func hostIsolate(cmd schema.ResponseCommand) schema.ResponseResult {
	server := extractServerHost(cmd.Reason)
	if server == "" {
		server = "127.0.0.1"
	}
	handler := NewNetworkHandler(zap.NewNop(), server, nil)
	if _, err := handler.Execute(context.Background(), map[string]interface{}{"action": "isolate"}); err != nil {
		return fail(cmd, fmt.Sprintf("host isolation failed: %v", err))
	}
	return ok(cmd, "host isolated")
}

func ok(cmd schema.ResponseCommand, msg string) schema.ResponseResult {
	return schema.ResponseResult{
		SchemaVersion: schema.SchemaVersionV1,
		CommandID:     cmd.CommandID,
		EndpointID:    cmd.EndpointID,
		Action:        cmd.Action,
		Success:       true,
		Message:       msg,
	}
}

func fail(cmd schema.ResponseCommand, msg string) schema.ResponseResult {
	return schema.ResponseResult{
		SchemaVersion: schema.SchemaVersionV1,
		CommandID:     cmd.CommandID,
		EndpointID:    cmd.EndpointID,
		Action:        cmd.Action,
		Success:       false,
		Message:       msg,
	}
}

func extractServerHost(reason string) string {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		return host
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return trimmed
	}
	return ""
}
