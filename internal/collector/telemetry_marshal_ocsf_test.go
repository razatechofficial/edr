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
			BaseEvent: schema.BaseEvent{EventType: schema.EventProcess},
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
	OCSFProductVersion = "test"
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
	if doc["kind"] != "process" {
		t.Fatalf("kind=%v", doc["kind"])
	}
	ocsfObj, ok := doc["ocsf"].(map[string]any)
	if !ok {
		t.Fatalf("missing ocsf object: %s", string(line))
	}
	if int(ocsfObj["class_uid"].(float64)) != ocsf.ClassUIDProcessActivity {
		t.Fatalf("class_uid=%v", ocsfObj["class_uid"])
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
	if _, ok := doc["ocsf"]; !ok {
		t.Fatalf("missing ocsf: %s", string(line))
	}
}
