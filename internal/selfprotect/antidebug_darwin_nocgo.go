//go:build darwin && !cgo

package selfprotect

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

const ptDenyAttach = 31

// DetectDebugger checks for debugger attachment on macOS without cgo.
// Falls back to checking DYLD environment variables and sysctl via CLI.
func DetectDebugger() bool {
	if sysctlTraced() {
		return true
	}
	for _, env := range []string{"DYLD_INSERT_LIBRARIES", "MallocStackLogging"} {
		if os.Getenv(env) != "" {
			return true
		}
	}
	return false
}

func sysctlTraced() bool {
	out, err := exec.Command("sysctl", "kern.proc.pid."+fmt.Sprint(os.Getpid())).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "P_TRACED")
}

// ProtectProcess issues ptrace(PT_DENY_ATTACH) to prevent future debugger
// attachment on macOS.
func ProtectProcess() error {
	_, _, errno := unix.RawSyscall(unix.SYS_PTRACE, ptDenyAttach, 0, 0)
	if errno != 0 {
		return fmt.Errorf("antidebug: PT_DENY_ATTACH: %v", errno)
	}
	return nil
}
