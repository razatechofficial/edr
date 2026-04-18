package selfprotect

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"go.uber.org/zap"
)

// RequiredLinuxCapabilities lists the CAP_* capabilities required for full
// EDR agent operation without running as root.
var RequiredLinuxCapabilities = []string{
	"cap_sys_ptrace",   // process inspection, anti-debug
	"cap_kill",         // process termination
	"cap_net_admin",    // network isolation (iptables)
	"cap_net_raw",      // raw socket for network monitoring
	"cap_dac_read_search", // reading /proc and log files
	"cap_sys_admin",    // eBPF program loading
	"cap_fowner",       // file quarantine across ownership boundaries
}

// CheckPrivileges validates that the agent has sufficient OS privileges.
// It returns warnings for missing capabilities rather than failing hard,
// allowing degraded operation.
func CheckPrivileges(logger *zap.Logger) []string {
	var warnings []string

	switch runtime.GOOS {
	case "linux":
		warnings = checkLinuxPrivileges(logger)
	case "darwin":
		warnings = checkDarwinPrivileges(logger)
	case "windows":
		warnings = checkWindowsPrivileges(logger)
	}

	for _, w := range warnings {
		logger.Warn("privilege check", zap.String("warning", w))
	}

	return warnings
}

func checkLinuxPrivileges(logger *zap.Logger) []string {
	var warnings []string

	if os.Getuid() == 0 {
		logger.Info("running as root — all capabilities available")
		return nil
	}

	capData, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", os.Getpid()))
	if err != nil {
		return []string{"cannot read /proc/self/status: " + err.Error()}
	}

	capLine := ""
	for _, line := range strings.Split(string(capData), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			capLine = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			break
		}
	}

	if capLine == "" {
		warnings = append(warnings, "could not determine effective capabilities")
	} else {
		logger.Info("effective capabilities", zap.String("cap_eff", capLine))
	}

	essentialPaths := []string{"/proc/net/tcp", "/var/log/auth.log", "/var/log/secure"}
	for _, p := range essentialPaths {
		if _, err := os.Stat(p); err != nil {
			if os.IsPermission(err) {
				warnings = append(warnings, fmt.Sprintf("no read access to %s", p))
			}
		}
	}

	return warnings
}

func checkDarwinPrivileges(logger *zap.Logger) []string {
	var warnings []string
	if os.Getuid() != 0 {
		warnings = append(warnings, "not running as root — some features (process kill, network isolation) may fail")
	}
	return warnings
}

func checkWindowsPrivileges(_ *zap.Logger) []string {
	return []string{"privilege checking not yet implemented on Windows"}
}
