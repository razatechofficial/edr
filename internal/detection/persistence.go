package detection

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// PersistenceDetector identifies persistence mechanism installation across
// Linux, macOS, and Windows. It detects systemd services/timers, crontab
// modifications, shell profile changes, LaunchDaemon/LaunchAgent plists,
// registry Run keys, scheduled tasks, service installation, DLL search order
// hijacking, and kernel module loading.
type PersistenceDetector struct {
	logger *zap.Logger
}

// NewPersistenceDetector creates a PersistenceDetector.
func NewPersistenceDetector(logger *zap.Logger) *PersistenceDetector {
	return &PersistenceDetector{logger: logger}
}

// Name returns the detector identifier.
func (d *PersistenceDetector) Name() string { return "persistence" }

// Analyze evaluates file and process events for persistence installation.
// The target OS is inferred from the event metadata; if absent, the runtime
// OS is used.
func (d *PersistenceDetector) Analyze(event interface{}, correlator *Correlator) []*events.Alert {
	pid := extractPID(event)
	if pid == 0 {
		return nil
	}

	osName := strings.ToLower(extractOS(event))
	if osName == "" {
		osName = runtime.GOOS
	}

	var alerts []*events.Alert
	switch osName {
	case "linux":
		alerts = d.checkLinux(event, pid, correlator)
	case "darwin":
		alerts = d.checkMacOS(event, pid, correlator)
	case "windows":
		alerts = d.checkWindows(event, pid, correlator)
	default:
		alerts = append(alerts, d.checkLinux(event, pid, correlator)...)
		alerts = append(alerts, d.checkMacOS(event, pid, correlator)...)
		alerts = append(alerts, d.checkWindows(event, pid, correlator)...)
	}
	return alerts
}

// Reset is a no-op; the detector is stateless.
func (d *PersistenceDetector) Reset() {}

// ---------------------------------------------------------------------------
// Linux persistence
// ---------------------------------------------------------------------------

type persistRule struct {
	pathPattern string
	cmdPattern  string
	ruleID      string
	title       string
	mitre       events.MITREAttack
}

var linuxPathRules = []persistRule{
	{pathPattern: "/etc/systemd/system/", ruleID: "PERSIST-L01", title: "Systemd service installation",
		mitre: events.MITREAttack{TechniqueID: "T1543.002", TechniqueName: "Systemd Service", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/lib/systemd/system/", ruleID: "PERSIST-L01", title: "Systemd service installation",
		mitre: events.MITREAttack{TechniqueID: "T1543.002", TechniqueName: "Systemd Service", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/etc/systemd/user/", ruleID: "PERSIST-L01", title: "Systemd user service installation",
		mitre: events.MITREAttack{TechniqueID: "T1543.002", TechniqueName: "Systemd Service", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/etc/cron", ruleID: "PERSIST-L02", title: "Crontab modification",
		mitre: events.MITREAttack{TechniqueID: "T1053.003", TechniqueName: "Cron", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/var/spool/cron/", ruleID: "PERSIST-L02", title: "Crontab modification",
		mitre: events.MITREAttack{TechniqueID: "T1053.003", TechniqueName: "Cron", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: ".bashrc", ruleID: "PERSIST-L03", title: "Shell profile modification",
		mitre: events.MITREAttack{TechniqueID: "T1546.004", TechniqueName: "Unix Shell Configuration Modification", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: ".bash_profile", ruleID: "PERSIST-L03", title: "Shell profile modification",
		mitre: events.MITREAttack{TechniqueID: "T1546.004", TechniqueName: "Unix Shell Configuration Modification", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: ".profile", ruleID: "PERSIST-L03", title: "Shell profile modification",
		mitre: events.MITREAttack{TechniqueID: "T1546.004", TechniqueName: "Unix Shell Configuration Modification", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: ".zshrc", ruleID: "PERSIST-L03", title: "Shell profile modification",
		mitre: events.MITREAttack{TechniqueID: "T1546.004", TechniqueName: "Unix Shell Configuration Modification", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/etc/ld.so.preload", ruleID: "PERSIST-L04", title: "LD_PRELOAD hijacking",
		mitre: events.MITREAttack{TechniqueID: "T1574.006", TechniqueName: "Dynamic Linker Hijacking", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/etc/ld.so.conf", ruleID: "PERSIST-L04", title: "Dynamic linker configuration change",
		mitre: events.MITREAttack{TechniqueID: "T1574.006", TechniqueName: "Dynamic Linker Hijacking", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/etc/init.d/", ruleID: "PERSIST-L05", title: "Init script installation",
		mitre: events.MITREAttack{TechniqueID: "T1037.004", TechniqueName: "RC Scripts", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/etc/rc.local", ruleID: "PERSIST-L05", title: "RC local modification",
		mitre: events.MITREAttack{TechniqueID: "T1037.004", TechniqueName: "RC Scripts", TacticID: "TA0003", TacticName: "Persistence"}},
}

var linuxCmdRules = []persistRule{
	{cmdPattern: "systemctl enable", ruleID: "PERSIST-L01", title: "Systemd service enabled",
		mitre: events.MITREAttack{TechniqueID: "T1543.002", TechniqueName: "Systemd Service", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "systemctl daemon-reload", ruleID: "PERSIST-L01", title: "Systemd daemon reload",
		mitre: events.MITREAttack{TechniqueID: "T1543.002", TechniqueName: "Systemd Service", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "crontab -", ruleID: "PERSIST-L02", title: "Crontab modification via command",
		mitre: events.MITREAttack{TechniqueID: "T1053.003", TechniqueName: "Cron", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "insmod ", ruleID: "PERSIST-L06", title: "Kernel module loading",
		mitre: events.MITREAttack{TechniqueID: "T1547.006", TechniqueName: "Kernel Modules and Extensions", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "modprobe ", ruleID: "PERSIST-L06", title: "Kernel module loading",
		mitre: events.MITREAttack{TechniqueID: "T1547.006", TechniqueName: "Kernel Modules and Extensions", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "chmod +s", ruleID: "PERSIST-L07", title: "SUID binary creation",
		mitre: events.MITREAttack{TechniqueID: "T1548.001", TechniqueName: "Setuid and Setgid", TacticID: "TA0004", TacticName: "Privilege Escalation"}},
	{cmdPattern: "chmod u+s", ruleID: "PERSIST-L07", title: "SUID binary creation",
		mitre: events.MITREAttack{TechniqueID: "T1548.001", TechniqueName: "Setuid and Setgid", TacticID: "TA0004", TacticName: "Privilege Escalation"}},
}

func (d *PersistenceDetector) checkLinux(event interface{}, pid uint32, correlator *Correlator) []*events.Alert {
	return d.matchRules(event, pid, correlator, linuxPathRules, linuxCmdRules)
}

// ---------------------------------------------------------------------------
// macOS persistence
// ---------------------------------------------------------------------------

var macosPathRules = []persistRule{
	{pathPattern: "/library/launchdaemons/", ruleID: "PERSIST-M01", title: "LaunchDaemon installation",
		mitre: events.MITREAttack{TechniqueID: "T1543.004", TechniqueName: "Launch Daemon", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/library/launchagents/", ruleID: "PERSIST-M02", title: "LaunchAgent installation",
		mitre: events.MITREAttack{TechniqueID: "T1543.001", TechniqueName: "Launch Agent", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "launchagents/", ruleID: "PERSIST-M02", title: "User LaunchAgent installation",
		mitre: events.MITREAttack{TechniqueID: "T1543.001", TechniqueName: "Launch Agent", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/library/startupitems/", ruleID: "PERSIST-M03", title: "Startup item installation",
		mitre: events.MITREAttack{TechniqueID: "T1037.005", TechniqueName: "Startup Items", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "/library/extensions/", ruleID: "PERSIST-M04", title: "Kernel extension installation",
		mitre: events.MITREAttack{TechniqueID: "T1547.006", TechniqueName: "Kernel Modules and Extensions", TacticID: "TA0003", TacticName: "Persistence"}},
}

var macosCmdRules = []persistRule{
	{cmdPattern: "launchctl load", ruleID: "PERSIST-M01", title: "LaunchDaemon/Agent loaded",
		mitre: events.MITREAttack{TechniqueID: "T1543.004", TechniqueName: "Launch Daemon", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "launchctl submit", ruleID: "PERSIST-M01", title: "LaunchDaemon/Agent submitted",
		mitre: events.MITREAttack{TechniqueID: "T1543.004", TechniqueName: "Launch Daemon", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "kextload", ruleID: "PERSIST-M04", title: "Kernel extension loaded",
		mitre: events.MITREAttack{TechniqueID: "T1547.006", TechniqueName: "Kernel Modules and Extensions", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "defaults write loginwindow", ruleID: "PERSIST-M05", title: "Login item modification",
		mitre: events.MITREAttack{TechniqueID: "T1547.015", TechniqueName: "Login Items", TacticID: "TA0003", TacticName: "Persistence"}},
}

func (d *PersistenceDetector) checkMacOS(event interface{}, pid uint32, correlator *Correlator) []*events.Alert {
	return d.matchRules(event, pid, correlator, macosPathRules, macosCmdRules)
}

// ---------------------------------------------------------------------------
// Windows persistence
// ---------------------------------------------------------------------------

var windowsPathRules = []persistRule{
	{pathPattern: "\\currentversion\\run", ruleID: "PERSIST-W01", title: "Registry Run key modification",
		mitre: events.MITREAttack{TechniqueID: "T1547.001", TechniqueName: "Registry Run Keys / Startup Folder", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "\\currentversion\\runonce", ruleID: "PERSIST-W01", title: "Registry RunOnce key modification",
		mitre: events.MITREAttack{TechniqueID: "T1547.001", TechniqueName: "Registry Run Keys / Startup Folder", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "\\start menu\\programs\\startup\\", ruleID: "PERSIST-W02", title: "Startup folder modification",
		mitre: events.MITREAttack{TechniqueID: "T1547.001", TechniqueName: "Registry Run Keys / Startup Folder", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "\\currentcontrolset\\services", ruleID: "PERSIST-W03", title: "Windows service registry modification",
		mitre: events.MITREAttack{TechniqueID: "T1543.003", TechniqueName: "Windows Service", TacticID: "TA0003", TacticName: "Persistence"}},
	{pathPattern: "\\tasks\\", ruleID: "PERSIST-W04", title: "Scheduled task file creation",
		mitre: events.MITREAttack{TechniqueID: "T1053.005", TechniqueName: "Scheduled Task", TacticID: "TA0003", TacticName: "Persistence"}},
}

var windowsCmdRules = []persistRule{
	{cmdPattern: "schtasks /create", ruleID: "PERSIST-W04", title: "Scheduled task creation",
		mitre: events.MITREAttack{TechniqueID: "T1053.005", TechniqueName: "Scheduled Task", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "schtasks.exe /create", ruleID: "PERSIST-W04", title: "Scheduled task creation",
		mitre: events.MITREAttack{TechniqueID: "T1053.005", TechniqueName: "Scheduled Task", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "sc create", ruleID: "PERSIST-W03", title: "Windows service installation",
		mitre: events.MITREAttack{TechniqueID: "T1543.003", TechniqueName: "Windows Service", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "sc.exe create", ruleID: "PERSIST-W03", title: "Windows service installation",
		mitre: events.MITREAttack{TechniqueID: "T1543.003", TechniqueName: "Windows Service", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "reg add", ruleID: "PERSIST-W01", title: "Registry modification via reg.exe",
		mitre: events.MITREAttack{TechniqueID: "T1547.001", TechniqueName: "Registry Run Keys / Startup Folder", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "new-service", ruleID: "PERSIST-W03", title: "PowerShell service creation",
		mitre: events.MITREAttack{TechniqueID: "T1543.003", TechniqueName: "Windows Service", TacticID: "TA0003", TacticName: "Persistence"}},
	{cmdPattern: "register-scheduledjob", ruleID: "PERSIST-W04", title: "PowerShell scheduled job",
		mitre: events.MITREAttack{TechniqueID: "T1053.005", TechniqueName: "Scheduled Task", TacticID: "TA0003", TacticName: "Persistence"}},
}

var windowsDLLHijackPaths = []string{
	"\\syswow64\\", "\\winsxs\\", "\\appdata\\local\\",
}

var windowsCOMHijackPatterns = []string{
	"\\classes\\clsid\\", "\\inprocserver32", "\\localserver32",
}

func (d *PersistenceDetector) checkWindows(event interface{}, pid uint32, correlator *Correlator) []*events.Alert {
	alerts := d.matchRules(event, pid, correlator, windowsPathRules, windowsCmdRules)

	path := strings.ToLower(extractFilePath(event))
	op := strings.ToLower(extractFileOperation(event))

	if (op == "create" || op == "write") && path != "" {
		if containsAny(path, windowsDLLHijackPaths...) && strings.HasSuffix(path, ".dll") {
			alerts = append(alerts, newAlert(
				"PERSIST-W05", "persistence", "DLL search order hijacking",
				fmt.Sprintf("PID %d dropped DLL in search-order hijack path: %s", pid, extractFilePath(event)),
				events.SeverityHigh,
				[]events.MITREAttack{
					{TechniqueID: "T1574.001", TechniqueName: "DLL Search Order Hijacking", TacticID: "TA0003", TacticName: "Persistence"},
				},
				[]string{"persistence", "dll_hijack"}, event,
			))
		}
		if containsAny(path, windowsCOMHijackPatterns...) {
			alerts = append(alerts, newAlert(
				"PERSIST-W06", "persistence", "COM object hijacking",
				fmt.Sprintf("PID %d modified COM registration: %s", pid, extractFilePath(event)),
				events.SeverityHigh,
				[]events.MITREAttack{
					{TechniqueID: "T1546.015", TechniqueName: "Component Object Model Hijacking", TacticID: "TA0003", TacticName: "Persistence"},
				},
				[]string{"persistence", "com_hijack"}, event,
			))
		}
	}
	return alerts
}

// ---------------------------------------------------------------------------
// Generic rule matching engine shared across platforms
// ---------------------------------------------------------------------------

func (d *PersistenceDetector) matchRules(event interface{}, pid uint32, correlator *Correlator, pathRules, cmdRules []persistRule) []*events.Alert {
	path := strings.ToLower(extractFilePath(event))
	cmd := strings.ToLower(extractCommandLine(event))
	op := strings.ToLower(extractFileOperation(event))

	var alerts []*events.Alert

	if (op == "create" || op == "write" || op == "modify") && path != "" {
		for _, r := range pathRules {
			if strings.Contains(path, r.pathPattern) {
				sev := d.severityForPersistence(pid, correlator)
				d.logger.Warn("persistence path detected",
					zap.Uint32("pid", pid), zap.String("rule", r.ruleID), zap.String("path", path))
				alerts = append(alerts, newAlert(
					r.ruleID, "persistence", r.title,
					fmt.Sprintf("PID %d: %s — %s", pid, r.title, extractFilePath(event)),
					sev, []events.MITREAttack{r.mitre},
					[]string{"persistence"}, event,
				))
				break
			}
		}
	}

	if cmd != "" {
		for _, r := range cmdRules {
			if strings.Contains(cmd, r.cmdPattern) {
				sev := d.severityForPersistence(pid, correlator)
				d.logger.Warn("persistence command detected",
					zap.Uint32("pid", pid), zap.String("rule", r.ruleID), zap.String("cmd", cmd))
				alerts = append(alerts, newAlert(
					r.ruleID, "persistence", r.title,
					fmt.Sprintf("PID %d: %s", pid, r.title),
					sev, []events.MITREAttack{r.mitre},
					[]string{"persistence"}, event,
				))
				break
			}
		}
	}

	return alerts
}

func (d *PersistenceDetector) severityForPersistence(pid uint32, correlator *Correlator) events.Severity {
	recentFiles := correlator.GetRecentFiles(pid, Window5m)
	for _, f := range recentFiles {
		fl := strings.ToLower(f)
		if containsAny(fl, "/tmp/", "\\temp\\", "/dev/shm/", "\\appdata\\") {
			return events.SeverityHigh
		}
	}
	return events.SeverityMedium
}
