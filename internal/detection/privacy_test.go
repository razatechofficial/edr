package detection

import (
	"testing"

	"github.com/razatechofficial/edr/internal/schema"
	"go.uber.org/zap"
)

func newTestPrivacyDetector(t *testing.T) (*PrivacyDetector, *Correlator) {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	d := NewPrivacyDetector(logger)
	c := NewCorrelator(logger)
	t.Cleanup(func() { c.Stop() })
	return d, c
}

func TestPrivacyScreenCaptureViaOperation(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.PrivacyEvent{
		BaseEvent:       schema.BaseEvent{EventType: schema.EventProcess},
		Operation:       "screen_capture",
		Service:         "CGDisplayStream",
		AccessingPID:    1001,
		AccessingProcess: "screencapture",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected screen capture alert")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-001 screen capture alert")
	}
}

func TestPrivacyScreenCaptureViaAuthGetTask(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.PrivacyEvent{
		BaseEvent:       schema.BaseEvent{EventType: schema.EventProcess},
		Operation:       "task_for_pid",
		Service:         "auth_get_task",
		AccessingPID:    1002,
		AccessingProcess: "malware (WindowServer)",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected screen capture alert for AUTH_GET_TASK")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-001 screen capture alert")
	}
}

func TestPrivacyScreenCaptureViaService(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.PrivacyEvent{
		BaseEvent:       schema.BaseEvent{EventType: schema.EventProcess},
		Operation:       "access",
		Service:         "AVCaptureScreenInput",
		AccessingPID:    1003,
		AccessingProcess: "obs",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected screen capture alert via service name")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-001 screen capture alert")
	}
}

func TestPrivacyScreenCaptureViaTCCService(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.PrivacyEvent{
		BaseEvent:       schema.BaseEvent{EventType: schema.EventProcess},
		Operation:       "TCC authorize",
		Service:         "kTCCServiceScreenCapture",
		AccessingPID:    1004,
		AccessingProcess: "suspicious_app",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected screen capture alert via TCC service")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-001 screen capture alert")
	}
}

func TestPrivacyKeyloggingViaAccessibility(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.PrivacyEvent{
		BaseEvent:       schema.BaseEvent{EventType: schema.EventProcess},
		Operation:       "TCC authorize",
		Service:         "kTCCServiceAccessibility",
		AccessingPID:    2001,
		AccessingProcess: "keylogger_app",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected keylogging alert via accessibility service")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-002" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-002 keylogging alert")
	}
}

func TestPrivacyKeyloggingViaCommandLine(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.ProcessEvent{
		BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
		PID:         2002,
		ProcessName: "powershell.exe",
		CommandLine: "powershell -Command Get-Keystrokes",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected keylogging alert via command line")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-002" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-002 keylogging alert")
	}
}

func TestPrivacyKeyloggingViaSetWindowsHookEx(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.ProcessEvent{
		BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
		PID:         2003,
		ProcessName: "malware.exe",
		CommandLine: "malware.exe --hook SetWindowsHookEx WH_KEYBOARD",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected keylogging alert via SetWindowsHookEx")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-002" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-002 keylogging alert")
	}
}

func TestPrivacyInputMonitoringDevInput(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
		ActorPID:  3001,
		Path:      "/dev/input/event0",
		Operation: "open",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected input monitoring alert via /dev/input")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-003 input monitoring alert")
	}
}

func TestPrivacyInputMonitoringQuartzEventTap(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.PrivacyEvent{
		BaseEvent:       schema.BaseEvent{EventType: schema.EventProcess},
		Operation:       "event_tap",
		Service:         "Quartz EventTap",
		AccessingPID:    3002,
		AccessingProcess: "macro_tool",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected input monitoring alert via Quartz EventTap")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-003 input monitoring alert")
	}
}

func TestPrivacyNormalProcessNoAlert(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.ProcessEvent{
		BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
		PID:         4001,
		ProcessName: "notepad.exe",
		CommandLine: "notepad.exe readme.txt",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) != 0 {
		t.Errorf("got %d alerts for normal process start, want 0", len(alerts))
	}
}

func TestPrivacyNormalFileEventNoAlert(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.FileEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
		ActorPID:  4002,
		Path:      "/home/user/Documents/report.pdf",
		Operation: "create",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) != 0 {
		t.Errorf("got %d alerts for normal file event, want 0", len(alerts))
	}
}

func TestPrivacyAuthEventNoPID(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.AuthEvent{
		BaseEvent: schema.BaseEvent{EventType: schema.EventAuth},
		User:      "root",
		Message:   "auth succeeded",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) != 0 {
		t.Errorf("got %d alerts for auth event with no PID, want 0", len(alerts))
	}
}

func TestPrivacyInputMonitoringViaCgPostEvent(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.ProcessEvent{
		BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
		PID:         3003,
		ProcessName: "mouse_mover",
		CommandLine: "mouse_mover -event CGPostMouseEvent",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected input monitoring alert via CGPostMouseEvent")
	}
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-003 input monitoring alert")
	}
}

func TestPrivacyInputMonitoringInputMonitoringService(t *testing.T) {
	t.Parallel()
	d, c := newTestPrivacyDetector(t)

	ev := &schema.PrivacyEvent{
		BaseEvent:       schema.BaseEvent{EventType: schema.EventProcess},
		Operation:       "TCC authorize",
		Service:         "kTCCServiceInputMonitoring",
		AccessingPID:    3004,
		AccessingProcess: "macro_recorder",
	}

	alerts := d.Analyze(ev, c)
	if len(alerts) == 0 {
		t.Fatal("expected keylogging alert via kTCCServiceInputMonitoring")
	}
	// Input monitoring could fire either PRIVACY-002 (keylogging) or PRIVACY-003 (input monitoring)
	found := false
	for _, a := range alerts {
		if a.RuleID == "PRIVACY-002" || a.RuleID == "PRIVACY-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PRIVACY-002 or PRIVACY-003 alert for input monitoring service")
	}
}
