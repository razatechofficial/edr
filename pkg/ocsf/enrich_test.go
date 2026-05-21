package ocsf

import "testing"

func TestEnrichDetectionMapProcess(t *testing.T) {
	t.Parallel()
	out := EnrichDetectionMap(map[string]interface{}{
		"event_type":   "process",
		"process_name": "powershell.exe",
		"process_path": "C:\\Windows\\System32\\powershell.exe",
		"command_line": "-enc ABC",
		"pid":          float64(1234),
	})
	if out["class_uid"] != ClassUIDProcessActivity {
		t.Fatalf("class_uid=%v", out["class_uid"])
	}
	if out["process_cmd_line"] != "-enc ABC" {
		t.Fatalf("process_cmd_line=%v", out["process_cmd_line"])
	}
	if v, ok := out["Image"]; ok && v != "" && v != nil {
		t.Fatalf("unexpected sigma alias Image=%v", v)
	}
}

func TestEnrichDetectionMapFile(t *testing.T) {
	t.Parallel()
	out := EnrichDetectionMap(map[string]interface{}{
		"event_type": "file",
		"path":       "/etc/passwd",
		"operation":  "write",
	})
	if out["file_path_ocsf"] != "/etc/passwd" {
		t.Fatalf("file_path_ocsf=%v", out["file_path_ocsf"])
	}
}
