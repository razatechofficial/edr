package detection

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// RootkitDetector identifies kernel-level tampering, hidden processes/modules,
// LD_PRELOAD manipulation, and other rootkit installation patterns.
type RootkitDetector struct {
	mu        sync.Mutex
	logger    *zap.Logger
	alerted   map[string]time.Time // dedup key → last alert time
}

// NewRootkitDetector creates a RootkitDetector.
func NewRootkitDetector(logger *zap.Logger) *RootkitDetector {
	return &RootkitDetector{
		logger:  logger,
		alerted: make(map[string]time.Time),
	}
}

func (d *RootkitDetector) Name() string { return "rootkit" }

func (d *RootkitDetector) Analyze(event interface{}, _ *Correlator) []*events.Alert {
	pe, ok := event.(*schema.ProcessEvent)
	if !ok {
		p, ok2 := event.(schema.ProcessEvent)
		if !ok2 {
			return nil
		}
		pe = &p
	}

	pid := uint32(pe.PID)
	if pid == 0 {
		return nil
	}

	var alerts []*events.Alert

	if a := d.checkHiddenModule(pe); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkHiddenSocket(pe); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkHiddenPID(pe); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkKernelModuleLoad(pe); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkLDPreload(pe); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkRootkitIOC(pe); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkHiddenPort(pe); a != nil {
		alerts = append(alerts, a)
	}

	return alerts
}

func (d *RootkitDetector) Reset() {
	d.mu.Lock()
	d.alerted = make(map[string]time.Time)
	d.mu.Unlock()
}

func (d *RootkitDetector) isDuplicate(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	last, ok := d.alerted[key]
	if ok && time.Since(last) < 5*time.Minute {
		return true
	}
	d.alerted[key] = time.Now()
	return false
}

// ---------------------------------------------------------------------------
// Rule: ROOTKIT-001 – Kernel module load
// ---------------------------------------------------------------------------

func (d *RootkitDetector) checkKernelModuleLoad(pe *schema.ProcessEvent) *events.Alert {
	if pe.ProcessName != "kernel_module_load" {
		return nil
	}
	moduleName := pe.ProcessPath
	if moduleName == "" {
		moduleName = pe.CommandLine
	}
	if d.isDuplicate("modload:" + moduleName) {
		return nil
	}
	d.logger.Warn("kernel module loaded", zap.String("module", moduleName))
	return d.newAlert(
		"ROOTKIT-001", "Kernel Module Load Detected",
		fmt.Sprintf("Kernel module loaded: %s — possible rootkit installation", moduleName),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1564", TechniqueName: "Hide Artifacts", TacticID: "TA0005", TacticName: "Defense Evasion"},
		},
		[]string{"rootkit", "kernel_module", "action:investigate"}, pe,
	)
}

// ---------------------------------------------------------------------------
// Rule: ROOTKIT-002 – Hidden kernel module
// ---------------------------------------------------------------------------

func (d *RootkitDetector) checkHiddenModule(pe *schema.ProcessEvent) *events.Alert {
	if pe.ProcessName != "posture.hidden_module" {
		return nil
	}
	kind := "" // sys_not_in_proc or proc_not_in_sys
	moduleName := pe.ProcessPath
	for _, t := range pe.Tags {
		if t == "sys_not_in_proc" || t == "proc_not_in_sys" {
			kind = t
			break
		}
	}
	if d.isDuplicate("hidden_mod:" + moduleName) {
		return nil
	}
	d.logger.Warn("hidden kernel module detected",
		zap.String("module", moduleName), zap.String("kind", kind))
	return d.newAlert(
		"ROOTKIT-002", "Hidden Kernel Module Detected",
		fmt.Sprintf("Hidden kernel module: %s (kind=%s) — rootkit hiding kernel code", moduleName, kind),
		events.SeverityCritical,
		[]events.MITREAttack{
			{TechniqueID: "T1014", TechniqueName: "Rootkit", TacticID: "TA0005", TacticName: "Defense Evasion"},
			{TechniqueID: "T1564", TechniqueName: "Hide Artifacts", TacticID: "TA0005", TacticName: "Defense Evasion"},
		},
		[]string{"rootkit", "hidden_module", "action:host_isolate", "action:investigate"}, pe,
	)
}

// ---------------------------------------------------------------------------
// Rule: ROOTKIT-003 – Hidden socket
// ---------------------------------------------------------------------------

func (d *RootkitDetector) checkHiddenSocket(pe *schema.ProcessEvent) *events.Alert {
	if pe.ProcessName != "posture.hidden_socket" {
		return nil
	}
	quintuple := pe.CommandLine
	if d.isDuplicate("hidden_sock:" + quintuple) {
		return nil
	}
	d.logger.Warn("hidden socket detected", zap.String("quintuple", quintuple))
	return d.newAlert(
		"ROOTKIT-003", "Hidden Network Socket",
		fmt.Sprintf("Hidden socket: %s — rootkit hiding network connections", quintuple),
		events.SeverityCritical,
		[]events.MITREAttack{
			{TechniqueID: "T1014", TechniqueName: "Rootkit", TacticID: "TA0005", TacticName: "Defense Evasion"},
			{TechniqueID: "T1572", TechniqueName: "Protocol Tunneling", TacticID: "TA0011", TacticName: "Command and Control"},
		},
		[]string{"rootkit", "hidden_socket", "action:host_isolate", "action:investigate"}, pe,
	)
}

// ---------------------------------------------------------------------------
// Rule: ROOTKIT-004 – Hidden process
// ---------------------------------------------------------------------------

func (d *RootkitDetector) checkHiddenPID(pe *schema.ProcessEvent) *events.Alert {
	if pe.ProcessName != "posture.hidden_pid" {
		return nil
	}
	cmdLine := pe.CommandLine
	if d.isDuplicate("hidden_pid:" + cmdLine) {
		return nil
	}
	d.logger.Warn("hidden process detected", zap.String("command", cmdLine))
	return d.newAlert(
		"ROOTKIT-004", "Hidden Process Detected",
		fmt.Sprintf("Process exists but is hidden from /proc: %s — DKOM or kernel rootkit", cmdLine),
		events.SeverityCritical,
		[]events.MITREAttack{
			{TechniqueID: "T1014", TechniqueName: "Rootkit", TacticID: "TA0005", TacticName: "Defense Evasion"},
			{TechniqueID: "T1055", TechniqueName: "Process Injection", TacticID: "TA0005", TacticName: "Defense Evasion"},
		},
		[]string{"rootkit", "hidden_process", "action:host_isolate", "action:investigate", "action:memory_scan"}, pe,
	)
}

// ---------------------------------------------------------------------------
// Rule: ROOTKIT-005 – Hidden port (port hiding via rootkit)
// ---------------------------------------------------------------------------

func (d *RootkitDetector) checkHiddenPort(pe *schema.ProcessEvent) *events.Alert {
	if pe.ProcessName != "posture.hidden_port" {
		return nil
	}
	cmdLine := pe.CommandLine
	if d.isDuplicate("hidden_port:" + cmdLine) {
		return nil
	}
	d.logger.Warn("hidden port detected", zap.String("command", cmdLine))
	return d.newAlert(
		"ROOTKIT-005", "Hidden Listening Port",
		fmt.Sprintf("Port is active but hidden from /proc/net/tcp: %s — kernel rootkit", cmdLine),
		events.SeverityCritical,
		[]events.MITREAttack{
			{TechniqueID: "T1014", TechniqueName: "Rootkit", TacticID: "TA0005", TacticName: "Defense Evasion"},
			{TechniqueID: "T1572", TechniqueName: "Protocol Tunneling", TacticID: "TA0011", TacticName: "Command and Control"},
		},
		[]string{"rootkit", "hidden_port", "action:host_isolate", "action:investigate"}, pe,
	)
}

// ---------------------------------------------------------------------------
// Rule: ROOTKIT-006 – LD_PRELOAD manipulation
// ---------------------------------------------------------------------------

func (d *RootkitDetector) checkLDPreload(pe *schema.ProcessEvent) *events.Alert {
	hasTag := false
	for _, t := range pe.Tags {
		if t == "ld_so_preload_hash" || strings.Contains(t, "ld_preload") {
			hasTag = true
			break
		}
	}
	if !hasTag {
		cmd := strings.ToLower(pe.CommandLine)
		if !strings.Contains(cmd, "ld.so.preload") && !strings.Contains(cmd, "ld_preload") {
			return nil
		}
	}
	if d.isDuplicate("ldpreload:" + pe.ProcessPath) {
		return nil
	}
	d.logger.Warn("LD_PRELOAD manipulation detected",
		zap.String("process", pe.ProcessName), zap.String("cmd", pe.CommandLine))
	return d.newAlert(
		"ROOTKIT-006", "LD_PRELOAD Manipulation",
		fmt.Sprintf("LD_PRELOAD or /etc/ld.so.preload modified by PID %d — possible library hooking rootkit", pe.PID),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1574", TechniqueName: "Hijack Execution Flow", TacticID: "TA0005", TacticName: "Defense Evasion"},
			{TechniqueID: "T1014", TechniqueName: "Rootkit", TacticID: "TA0005", TacticName: "Defense Evasion"},
		},
		[]string{"rootkit", "ld_preload", "action:investigate", "action:file_scan"}, pe,
	)
}

// ---------------------------------------------------------------------------
// Rule: ROOTKIT-007 – Rootkit IOC path
// ---------------------------------------------------------------------------

var knownRootkitPaths = []string{
	"/dev/.udev",
	"/usr/bin/.sshd",
	"/sbin/.mgik",
	"/tmp/.ICE-unix",
	"/lib/libkeyutils.so.1.5",
	"/etc/hosts.deny.bak",
	"/usr/sbin/udhcpc",
	"/bin/.login",
}

func (d *RootkitDetector) checkRootkitIOC(pe *schema.ProcessEvent) *events.Alert {
	if pe.ProcessName != "posture.rootkit" {
		return nil
	}
	path := pe.ProcessPath
	if path == "" {
		path = pe.CommandLine
	}
	for _, known := range knownRootkitPaths {
		if strings.Contains(path, known) {
			if d.isDuplicate("rkioc:" + known) {
				continue
			}
			d.logger.Warn("rootkit IOC path detected", zap.String("path", known))
			return d.newAlert(
				"ROOTKIT-007", "Rootkit Artifact Path",
				fmt.Sprintf("Known rootkit file path present: %s", known),
				events.SeverityCritical,
				[]events.MITREAttack{
					{TechniqueID: "T1014", TechniqueName: "Rootkit", TacticID: "TA0005", TacticName: "Defense Evasion"},
				},
				[]string{"rootkit", "rootkit_ioc", "action:host_isolate", "action:file_scan"}, pe,
			)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (d *RootkitDetector) newAlert(ruleID, title, desc string, sev events.Severity, mitre []events.MITREAttack, tags []string, event interface{}) *events.Alert {
	return &events.Alert{
		RuleID:      ruleID,
		RuleName:    title,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Timestamp:   time.Now().UTC(),
		MITRE:       mitre,
		Tags:        tags,
		RawEvent:    event,
	}
}
