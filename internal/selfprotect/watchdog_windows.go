//go:build windows

package selfprotect

import "golang.org/x/sys/windows"

// stillActive is the Windows kernel sentinel for a process that has not yet
// terminated. NTSTATUS / Win32 documentation explicitly enumerates 259
// (STATUS_PENDING) as the exit-code value returned by GetExitCodeProcess
// for a still-running process.
const stillActive = 259

// processAlive returns true when the given PID is still running. Previously
// the cross-platform implementation used os.Process.Signal(0) which always
// returned false on Windows — the watchdog therefore declared the agent
// dead on every tick and entered a restart loop. This implementation uses
// OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION (the minimum right
// required to query exit code, available without SeDebugPrivilege) followed
// by GetExitCodeProcess. Both calls failing — handle open denial or query
// failure — are treated as "not alive" so a missing process is correctly
// surfaced for restart.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	return exitCode == stillActive
}
