package ocsf

import "testing"

func TestEnrichLinuxSigmaFieldsProcess(t *testing.T) {
	t.Parallel()
	out := SigmaEvalMap(map[string]interface{}{
		"os":                  "linux",
		"event_type":          "process",
		"process_path":        "/usr/bin/curl",
		"parent_process_path": "/bin/bash",
		"user":                "root",
		"image_sha256":        "abc123",
	})
	if out["Image"] != "/usr/bin/curl" {
		t.Fatalf("Image=%v", out["Image"])
	}
	if out["ParentImage"] != "/bin/bash" {
		t.Fatalf("ParentImage=%v", out["ParentImage"])
	}
	if out["User"] != "root" {
		t.Fatalf("User=%v", out["User"])
	}
	if out["Hashes"] != "SHA256=ABC123" {
		t.Fatalf("Hashes=%v", out["Hashes"])
	}
}

func TestEnrichLinuxSigmaFieldsFileEvent(t *testing.T) {
	t.Parallel()
	out := SigmaEvalMap(map[string]interface{}{
		"os":   "linux",
		"path": "/etc/cron.d/evil",
		"type": "file",
	})
	if out["TargetFilename"] != "/etc/cron.d/evil" {
		t.Fatalf("TargetFilename=%v", out["TargetFilename"])
	}
}
