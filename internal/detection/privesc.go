package detection

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

const sudoAnomalyThreshold = 10

// PrivescDetector identifies privilege escalation attempts including sudo
// frequency anomalies, SUID binary execution from unexpected locations,
// token manipulation, UAC bypass techniques, and kernel exploit patterns.
type PrivescDetector struct {
	logger *zap.Logger
}

// NewPrivescDetector creates a PrivescDetector.
func NewPrivescDetector(logger *zap.Logger) *PrivescDetector {
	return &PrivescDetector{logger: logger}
}

// Name returns the detector identifier.
func (d *PrivescDetector) Name() string { return "privesc" }

// Analyze evaluates process and file events for privilege escalation indicators.
func (d *PrivescDetector) Analyze(event interface{}, correlator *Correlator) []*events.Alert {
	pid := extractPID(event)
	if pid == 0 {
		return nil
	}

	var alerts []*events.Alert
	if a := d.checkSudoAnomaly(event, pid, correlator); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkSUIDBinary(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkSetuidCall(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkTokenManipulation(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkUACBypass(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkKernelExploit(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	return alerts
}

// Reset is a no-op; the detector is stateless.
func (d *PrivescDetector) Reset() {}

// ---------------------------------------------------------------------------
// Sudo frequency anomaly
// ---------------------------------------------------------------------------

func (d *PrivescDetector) checkSudoAnomaly(event interface{}, pid uint32, correlator *Correlator) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	if !strings.HasPrefix(cmd, "sudo ") && !containsAny(cmd, "/usr/bin/sudo", "doas ") {
		return nil
	}

	user := extractUser(event)
	if user == "" || user == "root" {
		return nil
	}

	recent := correlator.GetUserEvents(user, Window5m)
	sudoCount := 0
	for _, ev := range recent {
		c := strings.ToLower(extractCommandLine(ev))
		if strings.HasPrefix(c, "sudo ") || containsAny(c, "/usr/bin/sudo", "doas ") {
			sudoCount++
		}
	}
	if sudoCount < sudoAnomalyThreshold {
		return nil
	}

	d.logger.Warn("sudo frequency anomaly",
		zap.Uint32("pid", pid), zap.String("user", user), zap.Int("count", sudoCount))
	return newAlert(
		"PRIV-001", "privesc", "Sudo usage frequency anomaly",
		fmt.Sprintf("User %s executed sudo %d times in 5 minutes (PID %d)", user, sudoCount, pid),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1548.003", TechniqueName: "Sudo and Sudo Caching", TacticID: "TA0004", TacticName: "Privilege Escalation"},
		},
		[]string{"privesc", "sudo_abuse"}, event,
	)
}

// ---------------------------------------------------------------------------
// SUID binary from unexpected location
// ---------------------------------------------------------------------------

var unexpectedSUIDPaths = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/home/",
	"/opt/", "/root/", "/mnt/", "/media/",
}

func (d *PrivescDetector) checkSUIDBinary(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	path := strings.ToLower(extractFilePath(event))

	isSUID := containsAny(cmd, "chmod +s", "chmod u+s", "chmod g+s", "chmod 4755", "chmod 2755")

	if isSUID {
		for _, p := range unexpectedSUIDPaths {
			if strings.Contains(path, p) || containsAny(cmd, p) {
				d.logger.Warn("SUID binary in unexpected location",
					zap.Uint32("pid", pid), zap.String("path", path))
				return newAlert(
					"PRIV-002", "privesc", "SUID binary in unexpected location",
					fmt.Sprintf("PID %d set SUID bit on binary in %s", pid, path),
					events.SeverityHigh,
					[]events.MITREAttack{
						{TechniqueID: "T1548.001", TechniqueName: "Setuid and Setgid", TacticID: "TA0004", TacticName: "Privilege Escalation"},
					},
					[]string{"privesc", "suid", "action:quarantine_file"}, event,
				)
			}
		}
	}

	// Execution of binaries from unexpected locations
	if path != "" && containsAny(path, unexpectedSUIDPaths...) {
		proc := strings.ToLower(extractProcessName(event))
		if proc != "" && !containsAny(proc, "sh", "bash", "python", "perl", "ruby", "node") {
			op := strings.ToLower(extractFileOperation(event))
			if op == "execute" {
				return newAlert(
					"PRIV-002", "privesc", "Binary execution from unexpected location",
					fmt.Sprintf("PID %d executed binary from %s", pid, path),
					events.SeverityMedium,
					[]events.MITREAttack{
						{TechniqueID: "T1548.001", TechniqueName: "Setuid and Setgid", TacticID: "TA0004", TacticName: "Privilege Escalation"},
					},
					[]string{"privesc", "unexpected_exec"}, event,
				)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// setuid/setgid from unprivileged process
// ---------------------------------------------------------------------------

func (d *PrivescDetector) checkSetuidCall(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	if !containsAny(cmd, "setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid") {
		return nil
	}

	user := extractUser(event)
	if user == "root" || user == "SYSTEM" {
		return nil
	}

	d.logger.Warn("setuid/setgid from unprivileged process",
		zap.Uint32("pid", pid), zap.String("user", user))
	return newAlert(
		"PRIV-003", "privesc", "Setuid/setgid from unprivileged process",
		fmt.Sprintf("PID %d (user %s) performed setuid/setgid operation", pid, user),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1548.001", TechniqueName: "Setuid and Setgid", TacticID: "TA0004", TacticName: "Privilege Escalation"},
		},
		[]string{"privesc", "setuid"}, event,
	)
}

// ---------------------------------------------------------------------------
// Token manipulation (Windows)
// ---------------------------------------------------------------------------

func (d *PrivescDetector) checkTokenManipulation(event interface{}, pid uint32) *events.Alert {
	if runtime.GOOS != "windows" {
		return nil
	}
	cmd := strings.ToLower(extractCommandLine(event))
	if !containsAny(cmd,
		"adjusttokenprivileges", "impersonateloggedonuser", "duplicatetokenex",
		"createprocesswithtokenw", "setthreadtoken",
		"invoke-tokenmanipulation", "incognito", "getsystem") {
		return nil
	}

	d.logger.Warn("token manipulation detected", zap.Uint32("pid", pid))
	return newAlert(
		"PRIV-004", "privesc", "Token manipulation detected",
		fmt.Sprintf("PID %d performed Windows token manipulation", pid),
		events.SeverityCritical,
		[]events.MITREAttack{
			{TechniqueID: "T1134", TechniqueName: "Access Token Manipulation", TacticID: "TA0004", TacticName: "Privilege Escalation"},
		},
		[]string{"privesc", "token_manipulation", "action:kill_process"}, event,
	)
}

// ---------------------------------------------------------------------------
// UAC bypass
// ---------------------------------------------------------------------------

var uacBypassIndicators = []string{
	"fodhelper", "eventvwr", "sdclt", "computerdefaults",
	"slui", "cmstp", "mmc", "silentcleanup",
	"bypassuac", "bypass-uac", "uac bypass",
	"invoke-envbypassuac", "invoke-sdclt",
}

func (d *PrivescDetector) checkUACBypass(event interface{}, pid uint32) *events.Alert {
	// UAC is Windows-only; substring indicators like "mmc" false-positive on other OSes.
	if runtime.GOOS != "windows" {
		return nil
	}
	cmd := strings.ToLower(extractCommandLine(event))
	proc := strings.ToLower(extractProcessName(event))
	if !containsAny(cmd, uacBypassIndicators...) && !containsAny(proc, uacBypassIndicators...) {
		return nil
	}

	d.logger.Warn("UAC bypass technique detected", zap.Uint32("pid", pid))
	return newAlert(
		"PRIV-005", "privesc", "UAC bypass technique detected",
		fmt.Sprintf("PID %d employed UAC bypass technique", pid),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1548.002", TechniqueName: "Bypass User Account Control", TacticID: "TA0004", TacticName: "Privilege Escalation"},
		},
		[]string{"privesc", "uac_bypass", "action:kill_process"}, event,
	)
}

// ---------------------------------------------------------------------------
// Kernel exploit patterns
// ---------------------------------------------------------------------------

var kernelExploitPatterns = []string{
	"dirtypipe", "dirtycow", "pwnkit", "pkexec",
	"polkit", "overlayfs", "cve-", "exploit",
	"roottool", "rootkit", "priv_esc",
	"kernelexploit", "kernel_exploit",
}

func (d *PrivescDetector) checkKernelExploit(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	proc := strings.ToLower(extractProcessName(event))
	path := strings.ToLower(extractFilePath(event))

	if !containsAny(cmd, kernelExploitPatterns...) &&
		!containsAny(proc, kernelExploitPatterns...) &&
		!containsAny(path, kernelExploitPatterns...) {
		return nil
	}

	d.logger.Warn("kernel exploit pattern detected", zap.Uint32("pid", pid))
	return newAlert(
		"PRIV-006", "privesc", "Kernel exploit pattern detected",
		fmt.Sprintf("PID %d shows kernel exploit indicators", pid),
		events.SeverityCritical,
		[]events.MITREAttack{
			{TechniqueID: "T1068", TechniqueName: "Exploitation for Privilege Escalation", TacticID: "TA0004", TacticName: "Privilege Escalation"},
		},
		[]string{"privesc", "kernel_exploit", "action:kill_process", "action:host_isolate"}, event,
	)
}
