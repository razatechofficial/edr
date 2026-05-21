package ocsf

import "testing"

func TestCELActivationMapProcess(t *testing.T) {
	t.Parallel()
	env := map[string]interface{}{
		"class_uid":  ClassUIDProcessActivity,
		"class_name": ClassProcessActivity,
		"process": map[string]interface{}{
			"cmd_line": "-enc ABC",
			"file": map[string]interface{}{
				"name": "powershell.exe",
				"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			},
		},
	}
	out := CELActivationMap(env)
	if out["class_uid"] != ClassUIDProcessActivity {
		t.Fatalf("class_uid=%v", out["class_uid"])
	}
	if out["process_cmd_line"] != "-enc ABC" {
		t.Fatalf("process_cmd_line=%v", out["process_cmd_line"])
	}
	if out["ocsf"] == nil {
		t.Fatal("expected nested ocsf reference")
	}
}

func TestSigmaEvalMapAddsSigmaFields(t *testing.T) {
	t.Parallel()
	in := CELActivationMap(map[string]interface{}{
		"class_uid": ClassUIDProcessActivity,
		"process": map[string]interface{}{
			"cmd_line": "whoami",
			"file":     map[string]interface{}{"path": "/bin/bash"},
		},
	})
	out := SigmaEvalMap(in)
	if out["Image"] != "/bin/bash" {
		t.Fatalf("Image=%v", out["Image"])
	}
	if out["CommandLine"] != "whoami" {
		t.Fatalf("CommandLine=%v", out["CommandLine"])
	}
}

func TestOCSFEnvelopeFromFlatPreservesNested(t *testing.T) {
	t.Parallel()
	nested := map[string]interface{}{"class_uid": float64(2004), "class_name": ClassDetectionFinding}
	env := OCSFEnvelopeFromFlat(map[string]interface{}{"ocsf": nested})
	if env["class_uid"] != float64(2004) {
		t.Fatalf("class_uid=%v", env["class_uid"])
	}
}
