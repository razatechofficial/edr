package ocsf

import "testing"

func TestEnrichWindowsSigmaFieldsProcess(t *testing.T) {
	t.Parallel()
	out := SigmaEvalMap(map[string]interface{}{
		"os":                  "windows",
		"event_type":          "process",
		"process_path":        `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"parent_process_path": `C:\Windows\explorer.exe`,
		"user":                `CORP\alice`,
		"image_sha256":        "deadbeef",
	})
	if out["Image"] == "" {
		t.Fatalf("Image missing: %v", out)
	}
	if out["ParentImage"] == "" {
		t.Fatalf("ParentImage missing")
	}
	if out["User"] != `CORP\alice` {
		t.Fatalf("User=%v", out["User"])
	}
	if out["Hashes"] != "SHA256=DEADBEEF" {
		t.Fatalf("Hashes=%v", out["Hashes"])
	}
}

func TestEnrichWindowsSigmaFieldsRegistry(t *testing.T) {
	t.Parallel()
	out := SigmaEvalMap(map[string]interface{}{
		"os":        "windows",
		"event_type": "registry",
		"key_path":  `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Evil`,
		"new_data":  "C:\\malware.exe",
		"operation": "set_value",
	})
	if out["TargetObject"] == "" {
		t.Fatalf("TargetObject missing: %v", out)
	}
	if out["Details"] != "C:\\malware.exe" {
		t.Fatalf("Details=%v", out["Details"])
	}
	if out["EventType"] != "set_value" {
		t.Fatalf("EventType=%v", out["EventType"])
	}
}
