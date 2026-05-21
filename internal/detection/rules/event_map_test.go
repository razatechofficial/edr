package rules

import "testing"

func TestEventToMapOCSFNative(t *testing.T) {
	t.Parallel()
	m := EventToMap(map[string]interface{}{
		"event_type":   "process",
		"process_path": "/bin/bash",
		"process_name": "bash",
		"command_line": "whoami",
	})
	if m == nil {
		t.Fatal("nil map")
	}
	if m["class_uid"] != float64(1007) && m["class_uid"] != int64(1007) && m["class_uid"] != 1007 {
		t.Fatalf("class_uid=%v", m["class_uid"])
	}
	if m["process_file_path"] != "/bin/bash" {
		t.Fatalf("process_file_path=%v", m["process_file_path"])
	}
}
