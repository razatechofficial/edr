package rules

import "testing"

func TestEventToMapOCSFEnrichment(t *testing.T) {
	t.Parallel()
	m := EventToMap(map[string]interface{}{
		"event_type":   "process",
		"process_path": "/bin/bash",
		"process_name": "bash",
	})
	if m == nil {
		t.Fatal("nil map")
	}
	if m["Image"] != "/bin/bash" {
		t.Fatalf("Image=%v", m["Image"])
	}
	if m["ocsf.process.file.path"] != "/bin/bash" {
		t.Fatalf("ocsf path=%v", m["ocsf.process.file.path"])
	}
}
