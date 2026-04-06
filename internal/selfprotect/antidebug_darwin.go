//go:build darwin

package selfprotect

/*
#include <sys/types.h>
#include <sys/sysctl.h>
#include <string.h>
#include <unistd.h>

static int is_traced(void) {
	struct kinfo_proc info;
	int mib[4];
	size_t sz = sizeof(info);

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = getpid();

	memset(&info, 0, sizeof(info));
	if (sysctl(mib, 4, &info, &sz, NULL, 0) != 0) {
		return 0;
	}
	return (info.kp_proc.p_flag & P_TRACED) != 0;
}
*/
import "C"

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const ptDenyAttach = 31

// DetectDebugger returns true if a debugger is attached to the current
// process. On macOS it uses sysctl to inspect the P_TRACED flag and checks
// for debug-related environment variables such as DYLD_INSERT_LIBRARIES.
func DetectDebugger() bool {
	if C.is_traced() != 0 {
		return true
	}
	for _, env := range []string{"DYLD_INSERT_LIBRARIES", "MallocStackLogging"} {
		if os.Getenv(env) != "" {
			return true
		}
	}
	return false
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
