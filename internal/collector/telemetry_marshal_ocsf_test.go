package collector

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

func TestEnsureTelemetryOCSFProcess(t *testing.T) {
	t.Parallel()
	tel := &Telemetry{
		Process: &schema.ProcessEvent{
			BaseEvent:   schema.BaseEvent{EventType: schema.EventProcess},
			ProcessName: "a.exe",
		},
	}
	EnsureTelemetryOCSF(tel)
	if len(tel.Process.OCSF) == 0 {
		t.Fatal("expected OCSF on process base event")
	}
}

func TestEnsureTelemetryOCSFRegistry(t *testing.T) {
	t.Parallel()
	tel := &Telemetry{
		Registry: &schema.RegistryEvent{
			BaseEvent: schema.BaseEvent{EventType: schema.EventRegistry},
			KeyPath:   `HKLM\Software\Test`,
			Operation: "set",
		},
	}
	EnsureTelemetryOCSF(tel)
	if tel.Registry.OCSF == nil {
		t.Fatal("expected OCSF on registry event")
	}
}

func TestMarshalTelemetryLineIncludesOCSFProcess(t *testing.T) {
	t.Parallel()
	SetOCSFProductVersion("test")
	line, err := MarshalTelemetryLine(&Telemetry{
		Process: &schema.ProcessEvent{
			BaseEvent: schema.BaseEvent{
				EventType: schema.EventProcess,
				Timestamp: time.Now().UTC(),
			},
			ProcessName: "cmd.exe",
			CommandLine: "whoami",
			PID:         100,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(line, &doc); err != nil {
		t.Fatal(err)
	}
	if int(doc["class_uid"].(float64)) != ocsf.ClassUIDProcessActivity {
		t.Fatalf("class_uid=%v", doc["class_uid"])
	}
	if doc["kind"] != nil {
		t.Fatalf("unexpected legacy kind field: %v", doc["kind"])
	}
}

func TestMarshalTelemetryLineIncludesOCSFFile(t *testing.T) {
	t.Parallel()
	line, err := MarshalTelemetryLine(&Telemetry{
		File: &schema.FileEvent{
			BaseEvent: schema.BaseEvent{EventType: schema.EventFile},
			Path:      "/etc/passwd",
			Operation: "write",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(line, &doc); err != nil {
		t.Fatal(err)
	}
	if int(doc["class_uid"].(float64)) != ocsf.ClassUIDFileActivity {
		t.Fatalf("class_uid=%v", doc["class_uid"])
	}
}

func TestMarshalTelemetryLineIncludesOCSFCompliance(t *testing.T) {
	t.Parallel()
	line, err := MarshalTelemetryLine(&Telemetry{
		Compliance: &schema.ComplianceFindingEvent{
			BaseEvent: schema.BaseEvent{
				EventType: schema.EventCompliance,
				Timestamp: time.Now().UTC(),
			},
			PolicyID: "posture",
			Title:    "Hidden PID",
			Result:   "failed",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(line, &doc); err != nil {
		t.Fatal(err)
	}
	if int(doc["class_uid"].(float64)) != ocsf.ClassUIDSecurityFinding {
		t.Fatalf("class_uid=%v", doc["class_uid"])
	}
}

func TestEnsureTelemetryOCSFPostureCompliance(t *testing.T) {
	t.Parallel()
	SetOCSFProductVersion("test")
	tel := postureFindingsToTelemetry("ep1", "host1", []PostureFinding{{
		ProbeID: "posture_hidden_pid",
		Title:   "Hidden PID",
		Detail:  "process hiding detected",
	}})
	if len(tel) != 1 {
		t.Fatalf("expected 1 telemetry, got %d", len(tel))
	}
	EnsureTelemetryOCSF(&tel[0])
	if tel[0].Compliance == nil || len(tel[0].Compliance.OCSF) == 0 {
		t.Fatal("expected OCSF on posture compliance finding")
	}
}

func TestEnsureTelemetryOCSFPrivilege(t *testing.T) {
	t.Parallel()
	tel := &Telemetry{
		Privilege: &schema.PrivilegeEvent{
			BaseEvent: schema.BaseEvent{EventType: schema.EventPrivilege},
			PID:       100,
			Operation: "setuid",
		},
	}
	EnsureTelemetryOCSF(tel)
	if tel.Privilege.OCSF == nil {
		t.Fatal("expected OCSF on privilege event")
	}
}

func TestEnsureTelemetryOCSFDNSNetwork(t *testing.T) {
	t.Parallel()
	tel := &Telemetry{
		Network: &schema.NetworkEvent{
			BaseEvent: schema.BaseEvent{EventType: schema.EventNetwork},
			Protocol:  "dns",
			Domain:    "evil.example.com",
		},
	}
	EnsureTelemetryOCSF(tel)
	if tel.Network.OCSF == nil {
		t.Fatal("expected OCSF on dns network event")
	}
	if int(tel.Network.OCSF["class_uid"].(float64)) != ocsf.ClassUIDDNSActivity {
		t.Fatalf("class_uid=%v", tel.Network.OCSF["class_uid"])
	}
}

func TestEnsureTelemetryOCSFScheduledJob(t *testing.T) {
	t.Parallel()
	tel := &Telemetry{
		Task: &schema.TaskEvent{
			BaseEvent: schema.BaseEvent{EventType: schema.EventProcess},
			TaskName:  "NightlyScan",
			Operation: "Create",
		},
	}
	EnsureTelemetryOCSF(tel)
	if tel.Task.OCSF == nil {
		t.Fatal("expected OCSF on task event")
	}
	if int(tel.Task.OCSF["class_uid"].(float64)) != ocsf.ClassUIDScheduledJobActivity {
		t.Fatalf("class_uid=%v", tel.Task.OCSF["class_uid"])
	}
}

func TestMarshalTelemetryBinaryIncludesOCSF(t *testing.T) {
	t.Parallel()
	SetOCSFProductVersion("test")
	src := &Telemetry{
		Process: &schema.ProcessEvent{
			BaseEvent: schema.BaseEvent{
				EventType: schema.EventProcess,
				Timestamp: time.Now().UTC(),
			},
			ProcessName: "a.exe",
			PID:         42,
		},
	}
	raw, err := MarshalTelemetryBinary(src)
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnmarshalTelemetryBinary(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Process == nil || len(out.Process.OCSF) == 0 {
		t.Fatal("expected OCSF after binary round-trip")
	}
}

func TestEnsureTelemetryOCSFTamper(t *testing.T) {
	t.Parallel()
	tel := &Telemetry{
		Tamper: &schema.TamperEvent{
			BaseEvent: schema.BaseEvent{Timestamp: time.Now().UTC()},
			Component: "agent_service",
			Message:   "stop attempted",
		},
	}
	EnsureTelemetryOCSF(tel)
	if tel.Tamper.OCSF == nil {
		t.Fatal("expected OCSF on tamper event")
	}
	if int(tel.Tamper.OCSF["class_uid"].(float64)) != ocsf.ClassUIDSecurityFinding {
		t.Fatalf("class_uid=%v", tel.Tamper.OCSF["class_uid"])
	}
}

func TestEnsureTelemetryOCSFPersistence(t *testing.T) {
	t.Parallel()
	tel := &Telemetry{
		Persistence: &schema.PersistenceEvent{
			BaseEvent:      schema.BaseEvent{Timestamp: time.Now().UTC()},
			Technique:      "LaunchAgent",
			ExecutablePath: "/Library/LaunchAgents/evil.plist",
			ItemType:       "plist",
		},
	}
	EnsureTelemetryOCSF(tel)
	if tel.Persistence.OCSF == nil {
		t.Fatal("expected OCSF on persistence event")
	}
	if int(tel.Persistence.OCSF["class_uid"].(float64)) != ocsf.ClassUIDSecurityFinding {
		t.Fatalf("class_uid=%v", tel.Persistence.OCSF["class_uid"])
	}
}

func TestEnsureTelemetryOCSFCredential(t *testing.T) {
	t.Parallel()
	tel := &Telemetry{
		Credential: &schema.CredentialAccessEvent{
			BaseEvent:     schema.BaseEvent{Timestamp: time.Now().UTC()},
			Technique:     "lsass_dump",
			SourcePID:     100,
			SourceProcess: "mimikatz.exe",
			TargetPath:    `C:\Windows\System32\lsass.exe`,
		},
	}
	EnsureTelemetryOCSF(tel)
	if tel.Credential.OCSF == nil {
		t.Fatal("expected OCSF on credential event")
	}
	if int(tel.Credential.OCSF["class_uid"].(float64)) != ocsf.ClassUIDProcessActivity {
		t.Fatalf("class_uid=%v", tel.Credential.OCSF["class_uid"])
	}
}
