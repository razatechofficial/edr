package detection

import (
	"fmt"
	"strings"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// PrivacyDetector identifies screen capture, keylogging, and input monitoring
// activity by analyzing privacy authorization events, TCC access patterns, and
// sensor-accessing process behavior.
type PrivacyDetector struct {
	logger *zap.Logger
}

// NewPrivacyDetector creates a PrivacyDetector.
func NewPrivacyDetector(logger *zap.Logger) *PrivacyDetector {
	return &PrivacyDetector{logger: logger}
}

// Name returns the detector identifier.
func (d *PrivacyDetector) Name() string { return "privacy" }

// Analyze evaluates privacy and authorization events for screen capture,
// keylogging, and input monitoring indicators.
func (d *PrivacyDetector) Analyze(event interface{}, correlator *Correlator) []*events.Alert {
	pid := privacyExtractPID(event)
	if pid == 0 {
		return nil
	}

	var alerts []*events.Alert
	if a := d.checkScreenCapture(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkKeylogging(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkInputMonitoring(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	return alerts
}

// Reset is a no-op; the detector is stateless.
func (d *PrivacyDetector) Reset() {}

// ---------------------------------------------------------------------------
// Screen capture detection
// ---------------------------------------------------------------------------

var screenCaptureServices = []string{
	"cgdisplaystream",
	"cgdisplaycapture",
	"avcapturescreeninput",
	"cgwindowlistcreateimage",
	"cgwindowlistcreateimagearray",
	"sonomacreenshot",
	"qtcapture",
	"scscreen",
	"scstream",
	"sccontentfilter",
}

var screenCaptureSignals = []string{
	"screen_capture",
	"screen recording",
	"kTCCServiceScreenCapture",
	"com.apple.cgxwindowserver",
	"windowserver",
}

func (d *PrivacyDetector) checkScreenCapture(event interface{}, pid uint32) *events.Alert {
	svc := privacyExtractService(event)
	op := privacyExtractOperation(event)
	proc := privacyExtractProcess(event)

	lowerSvc := strings.ToLower(svc)
	lowerOp := strings.ToLower(op)

	// Match known screen capture service identifiers
	for _, sc := range screenCaptureServices {
		if strings.Contains(lowerSvc, sc) {
			return d.screenCaptureAlert(pid, proc, svc, event)
		}
	}

	// Match operation or service against known signals
	for _, sig := range screenCaptureSignals {
		lowerSig := strings.ToLower(sig)
		if strings.Contains(lowerOp, lowerSig) || strings.Contains(lowerSvc, lowerSig) {
			return d.screenCaptureAlert(pid, proc, op, event)
		}
	}

	// AUTH_GET_TASK on WindowServer (task_for_pid)
	if lowerSvc == "auth_get_task" && strings.Contains(strings.ToLower(proc), "windowserver") {
		return d.screenCaptureAlert(pid, proc, "task_for_pid on WindowServer", event)
	}

	return nil
}

func (d *PrivacyDetector) screenCaptureAlert(pid uint32, process, detail string, event interface{}) *events.Alert {
	d.logger.Warn("screen capture detected",
		zap.Uint32("pid", pid), zap.String("process", process))
	return newAlert(
		"PRIVACY-001", "privacy", "Screen capture detected",
		fmt.Sprintf("PID %d (%s) initiated screen capture: %s", pid, process, detail),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1113", TechniqueName: "Screen Capture", TacticID: "TA0009", TacticName: "Collection"},
		},
		[]string{"privacy", "screen_capture", "action:investigate"}, event,
	)
}

// ---------------------------------------------------------------------------
// Keylogging detection
// ---------------------------------------------------------------------------

var keyloggingServices = []string{
	"kttcserviceaccessibility",
	"accessibility",
	"kttcserviceinputmonitoring",
	"inputmonitoring",
}

var keyloggingOperations = []string{
	"keylogging",
	"keyboard",
	"keystroke",
	"keylog",
}

func (d *PrivacyDetector) checkKeylogging(event interface{}, pid uint32) *events.Alert {
	svc := privacyExtractService(event)
	op := privacyExtractOperation(event)
	proc := privacyExtractProcess(event)
	cmd := privacyExtractCmd(event)

	lowerSvc := strings.ToLower(svc)
	lowerOp := strings.ToLower(op)
	lowerCmd := strings.ToLower(cmd)

	// TCC Accessibility / Input Monitoring access
	for _, ks := range keyloggingServices {
		if strings.Contains(lowerSvc, ks) {
			return d.keyloggingAlert(pid, proc, "accessibility/input monitoring: "+svc, event)
		}
	}

	// Operation field match
	for _, ko := range keyloggingOperations {
		if strings.Contains(lowerOp, ko) {
			return d.keyloggingAlert(pid, proc, op, event)
		}
	}

	// Command-line indicators (Windows keylogging APIs)
	if containsAny(lowerCmd,
		"setwindowshookex",
		"getasynckeystate",
		"getkeystate",
		"getkeyboardstate",
		"mapvirtualkey",
		"registerrawinputdevices",
		"get-keystrokes",
		"invoke-keylogger",
		"windows.forms.keys",
	) {
		return d.keyloggingAlert(pid, proc, "keylogging API call detected in command line", event)
	}

	return nil
}

func (d *PrivacyDetector) keyloggingAlert(pid uint32, process, detail string, event interface{}) *events.Alert {
	d.logger.Warn("keylogging detected",
		zap.Uint32("pid", pid), zap.String("process", process))
	return newAlert(
		"PRIVACY-002", "privacy", "Keylogging detected",
		fmt.Sprintf("PID %d (%s) — %s", pid, process, detail),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1056.001", TechniqueName: "Input Capture: Keylogging", TacticID: "TA0009", TacticName: "Collection"},
		},
		[]string{"privacy", "keylogging", "action:investigate"}, event,
	)
}

// ---------------------------------------------------------------------------
// Input monitoring detection
// ---------------------------------------------------------------------------

var inputMonitoringSignals = []string{
	"/dev/input",
	"/dev/uinput",
	"iokit.*hid",
	"cgpostevent",
	"cgpostmouseevent",
	"cgpostkeyboardevent",
	"quartszeventtap",
	"chtapting",
	"event tap",
}

func (d *PrivacyDetector) checkInputMonitoring(event interface{}, pid uint32) *events.Alert {
	op := privacyExtractOperation(event)
	path := privacyExtractPath(event)
	svc := privacyExtractService(event)
	proc := privacyExtractProcess(event)

	lowerOp := strings.ToLower(op)
	lowerPath := strings.ToLower(path)
	lowerSvc := strings.ToLower(svc)

	// Direct input device access
	for _, sig := range inputMonitoringSignals {
		if strings.Contains(lowerPath, sig) {
			return d.inputMonitoringAlert(pid, proc, "input device access: "+path, event)
		}
		if strings.Contains(lowerSvc, sig) {
			return d.inputMonitoringAlert(pid, proc, "input service: "+svc, event)
		}
		if strings.Contains(lowerOp, sig) {
			return d.inputMonitoringAlert(pid, proc, "input operation: "+op, event)
		}
	}

	// Event tap API with correlator context
	if strings.Contains(lowerSvc, "eventtap") || strings.Contains(lowerOp, "eventtap") {
		return d.inputMonitoringAlert(pid, proc, "Quartz event tap API", event)
	}

	return nil
}

func (d *PrivacyDetector) inputMonitoringAlert(pid uint32, process, detail string, event interface{}) *events.Alert {
	d.logger.Warn("input monitoring detected",
		zap.Uint32("pid", pid), zap.String("process", process))
	return newAlert(
		"PRIVACY-003", "privacy", "Input monitoring detected",
		fmt.Sprintf("PID %d (%s) — %s", pid, process, detail),
		events.SeverityHigh,
		[]events.MITREAttack{
			{TechniqueID: "T1056", TechniqueName: "Input Capture", TacticID: "TA0009", TacticName: "Collection"},
		},
		[]string{"privacy", "input_monitoring", "action:investigate"}, event,
	)
}

// ---------------------------------------------------------------------------
// Event extractors for privacy events
// ---------------------------------------------------------------------------

func privacyExtractPID(event interface{}) uint32 {
	switch ev := event.(type) {
	case *schema.PrivacyEvent:
		return ev.AccessingPID
	case *schema.ProcessEvent:
		return uint32(ev.PID)
	case *schema.AuthEvent:
		return 0
	case *schema.FileEvent:
		return uint32(ev.ActorPID)
	}
	return 0
}

func privacyExtractProcess(event interface{}) string {
	switch ev := event.(type) {
	case *schema.PrivacyEvent:
		return ev.AccessingProcess
	case *schema.ProcessEvent:
		return ev.ProcessName
	case *schema.FileEvent:
		return ""
	case *schema.AuthEvent:
		return ""
	}
	return ""
}

func privacyExtractService(event interface{}) string {
	switch ev := event.(type) {
	case *schema.PrivacyEvent:
		return ev.Service
	case *schema.AuthEvent:
		return ev.Subsystem
	case *schema.ProcessEvent:
		return ""
	case *schema.FileEvent:
		return ""
	}
	return ""
}

func privacyExtractOperation(event interface{}) string {
	switch ev := event.(type) {
	case *schema.PrivacyEvent:
		return ev.Operation
	case *schema.AuthEvent:
		return ev.Message
	case *schema.ProcessEvent:
		return ev.CommandLine
	case *schema.FileEvent:
		return ev.Operation
	}
	return ""
}

func privacyExtractPath(event interface{}) string {
	switch ev := event.(type) {
	case *schema.FileEvent:
		return ev.Path
	case *schema.ProcessEvent:
		return ev.ProcessPath
	case *schema.PrivacyEvent:
		return ""
	case *schema.AuthEvent:
		return ""
	}
	return ""
}

func privacyExtractCmd(event interface{}) string {
	switch ev := event.(type) {
	case *schema.ProcessEvent:
		return ev.CommandLine
	case *schema.PrivacyEvent:
		return ev.Operation
	case *schema.AuthEvent:
		return ev.Message
	}
	return ""
}
