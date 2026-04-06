package detection

import (
	"fmt"
	"strings"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// LateralDetector identifies lateral movement techniques including PsExec,
// WMI remote execution, PowerShell remoting, SMB admin share access, and
// pass-the-hash authentication patterns. It uses the correlator to detect
// kill chains where credential theft precedes lateral movement.
type LateralDetector struct {
	logger *zap.Logger
}

// NewLateralDetector creates a LateralDetector.
func NewLateralDetector(logger *zap.Logger) *LateralDetector {
	return &LateralDetector{logger: logger}
}

// Name returns the detector identifier.
func (d *LateralDetector) Name() string { return "lateral" }

// Analyze evaluates network and process events for lateral movement indicators.
func (d *LateralDetector) Analyze(event interface{}, correlator *Correlator) []*events.Alert {
	pid := extractPID(event)
	if pid == 0 {
		return nil
	}

	var alerts []*events.Alert
	if a := d.checkPsExec(event, pid, correlator); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkWMI(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkPSRemoting(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkAdminShares(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkPassTheHash(event, pid); a != nil {
		alerts = append(alerts, a)
	}

	d.escalateOnKillChain(alerts, pid, correlator)
	return alerts
}

// Reset is a no-op; the detector is stateless.
func (d *LateralDetector) Reset() {}

// ---------------------------------------------------------------------------
// PsExec detection (SMB connection + service creation)
// ---------------------------------------------------------------------------

func (d *LateralDetector) checkPsExec(event interface{}, pid uint32, correlator *Correlator) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	proc := strings.ToLower(extractProcessName(event))
	port := extractDestPort(event)

	isPsExec := containsAny(cmd, "psexec", "\\psexesvc") || containsAny(proc, "psexec", "psexesvc")
	isSMBService := port == 445 && d.hasRecentServiceCreation(pid, correlator)

	if !isPsExec && !isSMBService {
		return nil
	}

	d.logger.Warn("PsExec activity detected", zap.Uint32("pid", pid))
	return newAlert(
		"LAT-001", "lateral", "PsExec lateral movement",
		fmt.Sprintf("PID %d shows PsExec-style lateral movement pattern", pid),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1021.002", TechniqueName: "SMB/Windows Admin Shares", TacticID: "TA0008", TacticName: "Lateral Movement"},
			{TechniqueID: "T1569.002", TechniqueName: "Service Execution", TacticID: "TA0002", TacticName: "Execution"},
		},
		[]string{"lateral_movement", "psexec", "action:kill_process"}, event,
	)
}

func (d *LateralDetector) hasRecentServiceCreation(pid uint32, correlator *Correlator) bool {
	for _, ev := range correlator.GetProcessEvents(pid, Window5m) {
		c := strings.ToLower(extractCommandLine(ev))
		if containsAny(c, "sc create", "sc.exe create", "new-service") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// WMI remote execution
// ---------------------------------------------------------------------------

func (d *LateralDetector) checkWMI(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	if !containsAny(cmd, "wmic /node:", "wmic.exe /node:", "invoke-wmimethod", "get-wmiobject",
		"wmiprvse", "winmgmt") {
		return nil
	}

	d.logger.Warn("WMI remote execution detected", zap.Uint32("pid", pid))
	return newAlert(
		"LAT-002", "lateral", "WMI remote execution",
		fmt.Sprintf("PID %d executed WMI remote command", pid),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1047", TechniqueName: "Windows Management Instrumentation", TacticID: "TA0002", TacticName: "Execution"},
		},
		[]string{"lateral_movement", "wmi"}, event,
	)
}

// ---------------------------------------------------------------------------
// PowerShell remoting
// ---------------------------------------------------------------------------

func (d *LateralDetector) checkPSRemoting(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	if !containsAny(cmd, "enter-pssession", "invoke-command", "new-pssession",
		"enable-psremoting", "winrm", "evil-winrm") {
		return nil
	}

	port := extractDestPort(event)
	if port == 5985 || port == 5986 || containsAny(cmd, "enter-pssession", "invoke-command") {
		d.logger.Warn("PowerShell remoting detected", zap.Uint32("pid", pid))
		return newAlert(
			"LAT-003", "lateral", "PowerShell remoting to remote host",
			fmt.Sprintf("PID %d initiated PowerShell remote session", pid),
			events.SeverityHigh,
			[]events.MITREAttack{
				{TechniqueID: "T1021.006", TechniqueName: "Windows Remote Management", TacticID: "TA0008", TacticName: "Lateral Movement"},
			},
			[]string{"lateral_movement", "ps_remoting"}, event,
		)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Admin share connections
// ---------------------------------------------------------------------------

func (d *LateralDetector) checkAdminShares(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	domain := strings.ToLower(extractDomain(event))

	hasAdminShare := containsAny(cmd, "$admin", "admin$", "c$", "d$", "ipc$") ||
		containsAny(domain, "$admin", "admin$")

	if !hasAdminShare {
		return nil
	}

	d.logger.Warn("admin share access", zap.Uint32("pid", pid))
	return newAlert(
		"LAT-004", "lateral", "SMB admin share connection",
		fmt.Sprintf("PID %d accessed administrative network share", pid),
		events.SeverityMedium,
		[]events.MITREAttack{
			{TechniqueID: "T1021.002", TechniqueName: "SMB/Windows Admin Shares", TacticID: "TA0008", TacticName: "Lateral Movement"},
		},
		[]string{"lateral_movement", "admin_share"}, event,
	)
}

// ---------------------------------------------------------------------------
// Pass-the-hash patterns
// ---------------------------------------------------------------------------

func (d *LateralDetector) checkPassTheHash(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	if !containsAny(cmd, "sekurlsa::pth", "pass-the-hash", "overpass",
		"invoke-smbexec", "invoke-wmiexec", "impacket", "smbexec", "wmiexec",
		"atexec", "dcomexec") {
		return nil
	}

	d.logger.Warn("pass-the-hash detected", zap.Uint32("pid", pid))
	return newAlert(
		"LAT-005", "lateral", "Pass-the-hash authentication",
		fmt.Sprintf("PID %d shows pass-the-hash lateral movement pattern", pid),
		events.SeverityCritical,
		[]events.MITREAttack{
			{TechniqueID: "T1550.002", TechniqueName: "Pass the Hash", TacticID: "TA0008", TacticName: "Lateral Movement"},
		},
		[]string{"lateral_movement", "pass_the_hash", "action:kill_process", "action:host_isolate"}, event,
	)
}

// ---------------------------------------------------------------------------
// Kill chain escalation
// ---------------------------------------------------------------------------

func (d *LateralDetector) escalateOnKillChain(alerts []*events.Alert, pid uint32, correlator *Correlator) {
	if len(alerts) == 0 {
		return
	}

	recent := correlator.GetProcessEvents(pid, Window1h)
	hasCredDump := false
	for _, ev := range recent {
		c := strings.ToLower(extractCommandLine(ev))
		if containsAny(c, "mimikatz", "secretsdump", "hashdump", "procdump -ma lsass") {
			hasCredDump = true
			break
		}
	}
	if !hasCredDump {
		return
	}

	for _, a := range alerts {
		a.Severity = events.SeverityCritical
		a.Tags = append(a.Tags, "kill_chain", "cred_then_lateral", "action:host_isolate")
		a.Description += " — preceded by credential dump activity"
	}
}
