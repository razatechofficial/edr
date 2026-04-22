package response

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ProcessHandler implements ActionHandler for process kill and suspend actions.
// It dispatches to platform-specific mechanisms via os/exec to remain compilable
// on all targets.
type ProcessHandler struct {
	logger    *zap.Logger
	protected map[string]struct{}
}

// NewProcessHandler creates a ProcessHandler. The protected list contains
// process names (case-insensitive) that must never be killed or suspended.
func NewProcessHandler(logger *zap.Logger, protected []string) *ProcessHandler {
	p := make(map[string]struct{}, len(protected))
	for _, name := range protected {
		p[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	return &ProcessHandler{logger: logger, protected: p}
}

// Execute performs a kill or suspend action based on the "mode" param.
// Required params: "pid" (int). Optional: "mode" ("kill"|"suspend"), "tree" (bool).
func (h *ProcessHandler) Execute(ctx context.Context, params map[string]interface{}) (out *StepResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			if h.logger != nil {
				h.logger.Error("process handler panicked", zap.Any("recover", r))
			}
			err = fmt.Errorf("process handler panic: %v", r)
			if out == nil {
				out = failResult(OpKillProcess, "handler panicked")
			}
		}
	}()
	pid, err := intParam(params, "pid")
	if err != nil {
		return failResult(OpKillProcess, "invalid pid parameter"), err
	}
	if pid <= 0 {
		return failResult(OpKillProcess, "pid must be positive"), fmt.Errorf("process handler: invalid pid %d", pid)
	}
	if pid == os.Getpid() {
		return failResult(OpKillProcess, "refusing self-termination"),
			fmt.Errorf("process handler: refusing to act on own pid %d", pid)
	}

	name := stringParam(params, "process_name")
	if h.isProtected(name) {
		return failResult(OpKillProcess, fmt.Sprintf("process %q is protected", name)),
			fmt.Errorf("process handler: %q is protected", name)
	}

	mode := stringParam(params, "mode")
	if mode == "" {
		mode = "kill"
	}
	tree := boolParam(params, "tree")

	switch mode {
	case "kill":
		if tree {
			if err := h.killTree(ctx, pid); err != nil {
				return failResult(OpKillProcess, err.Error()), err
			}
			return okResult(OpKillProcess, fmt.Sprintf("process tree rooted at %d terminated", pid)), nil
		}
		if err := h.kill(pid); err != nil {
			return failResult(OpKillProcess, err.Error()), err
		}
		return okResult(OpKillProcess, fmt.Sprintf("process %d terminated", pid)), nil

	case "suspend":
		if err := h.suspend(pid); err != nil {
			return failResult(OpSuspendProcess, err.Error()), err
		}
		return okResult(OpSuspendProcess, fmt.Sprintf("process %d suspended", pid)), nil

	default:
		return failResult(OpKillProcess, fmt.Sprintf("unknown mode %q", mode)),
			fmt.Errorf("process handler: unknown mode %q", mode)
	}
}

// Rollback resumes a previously suspended process or is a no-op for kill.
func (h *ProcessHandler) Rollback(ctx context.Context, params map[string]interface{}) error {
	mode := stringParam(params, "mode")
	if mode != "suspend" {
		return nil
	}
	pid, err := intParam(params, "pid")
	if err != nil || pid <= 0 {
		return fmt.Errorf("process handler rollback: invalid pid: %w", err)
	}
	return h.resume(pid)
}

func (h *ProcessHandler) isProtected(name string) bool {
	if name == "" {
		return false
	}
	_, ok := h.protected[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// kill sends SIGKILL (Unix) or calls TerminateProcess (Windows) via os.Process.
func (h *ProcessHandler) kill(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("process handler: find process %d: %w", pid, err)
	}
	if err := proc.Kill(); err != nil {
		return fmt.Errorf("process handler: kill %d: %w", pid, err)
	}
	return nil
}

// suspend sends SIGSTOP (Linux/macOS) or returns an error on Windows.
func (h *ProcessHandler) suspend(pid int) error {
	switch runtime.GOOS {
	case "linux", "darwin":
		out, err := exec.Command("kill", "-STOP", strconv.Itoa(pid)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("process handler: SIGSTOP %d: %w (%s)", pid, err, strings.TrimSpace(string(out)))
		}
		return nil
	case "windows":
		// On Windows builds with cgo, this would call SuspendThread via
		// kernel32.dll. Using pssuspend from Sysinternals as a fallback.
		out, err := exec.Command("pssuspend", strconv.Itoa(pid)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("process handler: suspend %d on windows: %w (%s)", pid, err, strings.TrimSpace(string(out)))
		}
		return nil
	default:
		return fmt.Errorf("process handler: suspend unsupported on %s", runtime.GOOS)
	}
}

// resume sends SIGCONT (Unix) to continue a stopped process.
func (h *ProcessHandler) resume(pid int) error {
	switch runtime.GOOS {
	case "linux", "darwin":
		out, err := exec.Command("kill", "-CONT", strconv.Itoa(pid)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("process handler: SIGCONT %d: %w (%s)", pid, err, strings.TrimSpace(string(out)))
		}
		return nil
	case "windows":
		out, err := exec.Command("pssuspend", "-r", strconv.Itoa(pid)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("process handler: resume %d on windows: %w (%s)", pid, err, strings.TrimSpace(string(out)))
		}
		return nil
	default:
		return fmt.Errorf("process handler: resume unsupported on %s", runtime.GOOS)
	}
}

// killTree terminates the target process and all its descendants.
func (h *ProcessHandler) killTree(ctx context.Context, pid int) error {
	children, err := h.listChildren(pid)
	if err != nil {
		h.logger.Warn("could not enumerate children, killing root only", zap.Int("pid", pid), zap.Error(err))
	}
	// Kill children first (leaves → root).
	for i := len(children) - 1; i >= 0; i-- {
		if killErr := h.kill(children[i]); killErr != nil {
			h.logger.Warn("failed to kill child", zap.Int("child_pid", children[i]), zap.Error(killErr))
		}
	}
	return h.kill(pid)
}

// listChildren returns PIDs of all descendant processes.
func (h *ProcessHandler) listChildren(pid int) ([]int, error) {
	switch runtime.GOOS {
	case "linux":
		return h.listChildrenLinux(pid)
	case "darwin":
		return h.listChildrenDarwin(pid)
	default:
		return nil, fmt.Errorf("child enumeration not supported on %s", runtime.GOOS)
	}
}

func (h *ProcessHandler) listChildrenLinux(pid int) ([]int, error) {
	// /proc/<pid>/task/<tid>/children contains space-separated child PIDs.
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	if err != nil {
		// Fallback: pgrep -P
		return h.childrenViaPgrep(pid)
	}
	return parseIntList(strings.Fields(string(raw)))
}

func (h *ProcessHandler) listChildrenDarwin(pid int) ([]int, error) {
	return h.childrenViaPgrep(pid)
}

func (h *ProcessHandler) childrenViaPgrep(pid int) ([]int, error) {
	out, err := exec.Command("pgrep", "-P", strconv.Itoa(pid)).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil // no children
		}
		return nil, fmt.Errorf("pgrep children of %d: %w", pid, err)
	}
	return parseIntList(strings.Fields(strings.TrimSpace(string(out))))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseIntList(strs []string) ([]int, error) {
	out := make([]int, 0, len(strs))
	for _, s := range strs {
		v, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

func intParam(params map[string]interface{}, key string) (int, error) {
	v, ok := params[key]
	if !ok {
		return 0, fmt.Errorf("missing param %q", key)
	}
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		return int(n), nil
	case string:
		return strconv.Atoi(n)
	default:
		return 0, fmt.Errorf("param %q: unsupported type %T", key, v)
	}
}

func stringParam(params map[string]interface{}, key string) string {
	v, ok := params[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func boolParam(params map[string]interface{}, key string) bool {
	v, ok := params[key]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func okResult(key OpKey, msg string) *StepResult {
	return &StepResult{
		Action:    key,
		Success:   true,
		Message:   msg,
		Timestamp: time.Now(),
	}
}

func failResult(key OpKey, msg string) *StepResult {
	return &StepResult{
		Action:    key,
		Success:   false,
		Message:   msg,
		Timestamp: time.Now(),
	}
}
