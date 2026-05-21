package ocsf

import "testing"

func TestBuildDetectionEnvelopeProcess(t *testing.T) {
	t.Parallel()
	env := BuildDetectionEnvelope(map[string]interface{}{
		"event_type":   "process",
		"process_name": "powershell.exe",
		"command_line": "powershell -enc ABC",
		"pid":          float64(4242),
	})
	if env["class_uid"] != ClassUIDProcessActivity {
		t.Fatalf("class_uid=%v", env["class_uid"])
	}
	proc, ok := env["process"].(map[string]interface{})
	if !ok {
		t.Fatal("missing process object")
	}
	if proc["cmd_line"] != "powershell -enc ABC" {
		t.Fatalf("cmd_line=%v", proc["cmd_line"])
	}
}

func TestEnrichDetectionMapNestedOCSF(t *testing.T) {
	t.Parallel()
	out := EnrichDetectionMap(map[string]interface{}{
		"event_type":   "process",
		"process_name": "cmd.exe",
		"command_line": "whoami",
	})
	if out["class_uid"] != ClassUIDProcessActivity {
		t.Fatalf("class_uid=%v", out["class_uid"])
	}
	if out["process_cmd_line"] != "whoami" {
		t.Fatalf("process_cmd_line=%v", out["process_cmd_line"])
	}
	ocsfObj, ok := out["ocsf"].(map[string]interface{})
	if !ok {
		t.Fatal("missing nested ocsf envelope")
	}
	if ocsfObj["class_uid"] != ClassUIDProcessActivity {
		t.Fatalf("nested class_uid=%v", ocsfObj["class_uid"])
	}
}
