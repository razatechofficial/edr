package detection

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// InjectionDetector identifies process injection techniques by analyzing
// command-line patterns, suspicious process loading, cross-process tool usage,
// and anomalous parent-child process relationships.
type InjectionDetector struct {
	logger *zap.Logger
}

// NewInjectionDetector creates an InjectionDetector.
func NewInjectionDetector(logger *zap.Logger) *InjectionDetector {
	return &InjectionDetector{logger: logger}
}

// Name returns the detector identifier.
func (d *InjectionDetector) Name() string { return "injection" }

// Analyze evaluates process events for injection indicators.
func (d *InjectionDetector) Analyze(event interface{}, correlator *Correlator) []*events.Alert {
	pid := extractPID(event)
	if pid == 0 {
		return nil
	}
	if runtime.GOOS == "linux" && isLikelyKernelThreadNoise(extractProcessName(event), pid) {
		return nil
	}

	var alerts []*events.Alert
	if a := d.checkInjectionTools(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkSuspiciousLoaders(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkHollowingPatterns(event, pid, correlator); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkReflectiveLoad(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	return alerts
}

// Reset is a no-op; the detector is stateless.
func (d *InjectionDetector) Reset() {}

// ---------------------------------------------------------------------------
// Known injection tools
// ---------------------------------------------------------------------------

var injectionToolPatterns = []string{
	"syringe", "shellcode", "meterpreter",
	"cobalt", "donut", "shellter", "pe_inject",
	"process_inject", "reflective", "runpe", "hollowing",
}

func isLikelyKernelThreadNoise(process string, pid uint32) bool {
	// Linux kernel threads often show bracketed names and low PIDs.
	if pid > 256 {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(process))
	if p == "" {
		return true
	}
	return strings.HasPrefix(p, "[") || strings.HasSuffix(p, "]")
}

func (d *InjectionDetector) checkInjectionTools(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	proc := strings.ToLower(extractProcessName(event))
	if cmd == "" && proc == "" {
		return nil
	}

	if !containsAny(cmd, injectionToolPatterns...) && !containsAny(proc, injectionToolPatterns...) {
		return nil
	}

	d.logger.Warn("injection tool detected",
		zap.Uint32("pid", pid), zap.String("process", extractProcessName(event)))

	return newAlert(
		"INJECT-001", "injection", "Process injection tool detected",
		fmt.Sprintf("PID %d executed a known injection tool: %s", pid, extractProcessName(event)),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1055", TechniqueName: "Process Injection", TacticID: "TA0005", TacticName: "Defense Evasion"},
			{TechniqueID: "T1055", TechniqueName: "Process Injection", TacticID: "TA0004", TacticName: "Privilege Escalation"},
		},
		[]string{"injection", "action:kill_process"}, event,
	)
}

// ---------------------------------------------------------------------------
// Suspicious loader patterns (living-off-the-land binaries)
// ---------------------------------------------------------------------------

type loaderPattern struct {
	cmd   string
	name  string
	mitre events.MITREAttack
}

var suspiciousLoaders = []loaderPattern{
	{cmd: "rundll32.exe javascript:", name: "Rundll32 script execution",
		mitre: events.MITREAttack{TechniqueID: "T1218.011", TechniqueName: "Rundll32", TacticID: "TA0005", TacticName: "Defense Evasion"}},
	{cmd: "rundll32 javascript:", name: "Rundll32 script execution",
		mitre: events.MITREAttack{TechniqueID: "T1218.011", TechniqueName: "Rundll32", TacticID: "TA0005", TacticName: "Defense Evasion"}},
	{cmd: "regsvr32 /s /n /u /i:", name: "Regsvr32 Squiblydoo",
		mitre: events.MITREAttack{TechniqueID: "T1218.010", TechniqueName: "Regsvr32", TacticID: "TA0005", TacticName: "Defense Evasion"}},
	{cmd: "mshta vbscript:", name: "MSHTA VBScript execution",
		mitre: events.MITREAttack{TechniqueID: "T1218.005", TechniqueName: "Mshta", TacticID: "TA0005", TacticName: "Defense Evasion"}},
	{cmd: "mshta javascript:", name: "MSHTA JavaScript execution",
		mitre: events.MITREAttack{TechniqueID: "T1218.005", TechniqueName: "Mshta", TacticID: "TA0005", TacticName: "Defense Evasion"}},
	{cmd: "certutil -urlcache", name: "Certutil remote download",
		mitre: events.MITREAttack{TechniqueID: "T1105", TechniqueName: "Ingress Tool Transfer", TacticID: "TA0011", TacticName: "Command and Control"}},
	{cmd: "certutil -decode", name: "Certutil payload decode",
		mitre: events.MITREAttack{TechniqueID: "T1140", TechniqueName: "Deobfuscate/Decode Files or Information", TacticID: "TA0005", TacticName: "Defense Evasion"}},
	{cmd: "bitsadmin /transfer", name: "BITS download",
		mitre: events.MITREAttack{TechniqueID: "T1197", TechniqueName: "BITS Jobs", TacticID: "TA0005", TacticName: "Defense Evasion"}},
}

func (d *InjectionDetector) checkSuspiciousLoaders(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	if cmd == "" {
		return nil
	}

	for _, lp := range suspiciousLoaders {
		if strings.Contains(cmd, lp.cmd) {
			d.logger.Warn("suspicious loader pattern",
				zap.Uint32("pid", pid), zap.String("pattern", lp.name))
			return newAlert(
				"INJECT-002", "injection", lp.name,
				fmt.Sprintf("PID %d: %s", pid, lp.name),
				events.SeverityHigh,
				[]events.MITREAttack{lp.mitre},
				[]string{"injection", "lolbin"}, event,
			)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Process hollowing heuristic
// ---------------------------------------------------------------------------

func (d *InjectionDetector) checkHollowingPatterns(event interface{}, pid uint32, correlator *Correlator) *events.Alert {
	proc := strings.ToLower(extractProcessName(event))
	path := strings.ToLower(extractFilePath(event))
	if proc == "" {
		return nil
	}

	// System processes spawned from non-standard paths
	systemProcs := map[string]string{
		"svchost.exe":  "\\system32\\",
		"lsass.exe":    "\\system32\\",
		"csrss.exe":    "\\system32\\",
		"smss.exe":     "\\system32\\",
		"services.exe": "\\system32\\",
		"wininit.exe":  "\\system32\\",
	}
	expected, isSystem := systemProcs[proc]
	if isSystem && path != "" && !strings.Contains(path, expected) {
		d.logger.Warn("possible process hollowing",
			zap.Uint32("pid", pid), zap.String("process", proc), zap.String("path", path))
		return newAlert(
			"INJECT-003", "injection", "Possible process hollowing",
			fmt.Sprintf("PID %d: system process %s running from unexpected path %s", pid, proc, path),
			events.SeverityCritical,
			[]events.MITREAttack{
				{TechniqueID: "T1055.012", TechniqueName: "Process Hollowing", TacticID: "TA0005", TacticName: "Defense Evasion"},
			},
			[]string{"injection", "hollowing", "action:kill_process"}, event,
		)
	}

	// Check for rapid process-memory tool sequences using correlator
	recent := correlator.GetProcessEvents(pid, Window30s)
	memToolCount := 0
	for _, ev := range recent {
		c := strings.ToLower(extractCommandLine(ev))
		if containsAny(c, "virtualallocex", "writeprocessmemory", "createremotethread",
			"ntwritevirtualmemory", "ntmapviewofsection", "queueuserapc") {
			memToolCount++
		}
	}
	if memToolCount >= 2 {
		return newAlert(
			"INJECT-004", "injection", "Cross-process memory manipulation sequence",
			fmt.Sprintf("PID %d performed %d cross-process memory operations in 30s", pid, memToolCount),
			events.SeverityCritical,
			[]events.MITREAttack{
				{TechniqueID: "T1055", TechniqueName: "Process Injection", TacticID: "TA0005", TacticName: "Defense Evasion"},
			},
			[]string{"injection", "cross_process", "action:kill_process"}, event,
		)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Reflective DLL / RWX memory indicators
// ---------------------------------------------------------------------------

func (d *InjectionDetector) checkReflectiveLoad(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	if cmd == "" {
		return nil
	}
	if !containsAny(cmd, "reflectiveloader", "invoke-reflectivepeinjection",
		"invoke-shellcode", "invoke-dllinjection", "-rwx", "page_execute_readwrite") {
		return nil
	}

	d.logger.Warn("reflective load indicator",
		zap.Uint32("pid", pid))
	return newAlert(
		"INJECT-005", "injection", "Reflective DLL loading detected",
		fmt.Sprintf("PID %d shows reflective loading or RWX memory indicators", pid),
		events.SeverityCritical,
		[]events.MITREAttack{
			{TechniqueID: "T1620", TechniqueName: "Reflective Code Loading", TacticID: "TA0005", TacticName: "Defense Evasion"},
		},
		[]string{"injection", "reflective_dll", "action:kill_process"}, event,
	)
}
