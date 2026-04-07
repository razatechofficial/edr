package response

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/razatechofficial/edr/internal/schema"
	"go.uber.org/zap"
)

type Responder struct {
	allowKill bool
	protected map[string]struct{}
}

func NewResponder(allowKill bool, protected []string) *Responder {
	p := make(map[string]struct{}, len(protected))
	for _, name := range protected {
		p[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	return &Responder{allowKill: allowKill, protected: p}
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
	nameKey := strings.ToLower(strings.TrimSpace(filepath.Base(cmd.ProcessName)))
	if nameKey == "" {
		nameKey = strings.ToLower(strings.TrimSpace(filepath.Base(cmd.FilePath)))
	}
	if nameKey == "" {
		nameKey = strings.ToLower(strings.TrimSpace(filepath.Base(cmd.Reason)))
	}
	if _, ok := r.protected[nameKey]; ok {
		return fail(cmd, "target process is protected")
	}
	if cmd.ProcessPID == os.Getpid() {
		return fail(cmd, "refusing self-termination")
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
