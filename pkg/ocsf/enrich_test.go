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
	if out["Image"] != "C:\\Windows\\System32\\powershell.exe" {
		t.Fatalf("Image=%v", out["Image"])
	}
	if out["process.file.name"] != "powershell.exe" {
		t.Fatalf("process.file.name=%v", out["process.file.name"])
	}
	if out["ocsf.class_uid"] != ClassUIDProcessActivity {
		t.Fatalf("class_uid=%v", out["ocsf.class_uid"])
	}
}

func TestEnrichDetectionMapFile(t *testing.T) {
	t.Parallel()
	out := EnrichDetectionMap(map[string]interface{}{
		"event_type": "file",
		"path":       "/etc/passwd",
		"operation":  "write",
	})
	if out["TargetFilename"] != "/etc/passwd" {
		t.Fatalf("TargetFilename=%v", out["TargetFilename"])
	}
	if out["file.path"] != "/etc/passwd" {
		t.Fatalf("file.path=%v", out["file.path"])
	}
}
