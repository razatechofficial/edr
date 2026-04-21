package collector

import (
	"runtime"
	"testing"
	"time"
)

func TestMapKernelJSONToTelemetry_ProcessESFStyle(t *testing.T) {
	raw := `{"type":"process","pid":4242,"ppid":1,"path":"/bin/bash","comm":"/bin/bash","args":"-c id","timestamp":"2020-01-02T15:04:05Z"}`
	tel := MapKernelJSONToTelemetry([]byte(raw), "ep1", "host1", "darwin", nil)
	if tel == nil || tel.Process == nil {
		t.Fatalf("expected process telemetry")
	}
	if tel.Process.PID != 4242 || tel.Process.PPID != 1 {
		t.Fatalf("pid/ppid: %+v", tel.Process)
	}
	if tel.Process.ProcessPath != "/bin/bash" {
		t.Fatalf("path: %q", tel.Process.ProcessPath)
	}
}

func TestMapKernelJSONToTelemetry_ETWProcess(t *testing.T) {
	raw := `{"type":"process","pid":100,"event_id":1,"image_name":"C:\\Windows\\System32\\cmd.exe","parent_pid":99,"timestamp":"2020-01-02T15:04:05Z"}`
	tel := MapKernelJSONToTelemetry([]byte(raw), "ep", "h", "windows", nil)
	if tel == nil || tel.Process == nil {
		t.Fatalf("expected process")
	}
	if tel.Process.ProcessPath != `C:\Windows\System32\cmd.exe` {
		t.Fatalf("image_name path: %q", tel.Process.ProcessPath)
	}
}

func TestMapKernelJSONToTelemetry_ETWProcessStartChildPID(t *testing.T) {
	raw := `{"type":"process","pid":100,"child_pid":101,"parent_pid":99,"timestamp":"2020-01-02T15:04:05Z"}`
	tel := MapKernelJSONToTelemetry([]byte(raw), "e", "h", "windows", nil)
	if tel == nil || tel.Process == nil || tel.Process.PID != 101 {
		t.Fatalf("expected PID=child, got %+v", tel.Process)
	}
}

func TestMapKernelJSONToTelemetry_ProcessExitPID(t *testing.T) {
	raw := `{"type":"process","pid":100,"exit_pid":101,"timestamp":"2020-01-02T15:04:05Z"}`
	tel := MapKernelJSONToTelemetry([]byte(raw), "e", "h", "linux", nil)
	if tel == nil || tel.Process == nil || tel.Process.PID != 101 {
		t.Fatalf("expected exit_pid as PID, got %+v", tel.Process)
	}
}

func TestMapKernelJSONToTelemetry_Registry(t *testing.T) {
	raw := `{"type":"registry","key_path":"HKLM\\Run","value_name":"x","operation":"set","timestamp":"2020-01-02T15:04:05Z"}`
	tel := MapKernelJSONToTelemetry([]byte(raw), "e", "h", "windows", nil)
	if tel == nil || tel.Registry == nil || tel.Registry.KeyPath != `HKLM\Run` {
		t.Fatalf("expected registry, got %+v", tel)
	}
}

func TestMapKernelJSONToTelemetry_Fork(t *testing.T) {
	raw := `{"type":"fork","pid":1,"child_pid":2,"clone_flags":256,"timestamp":"2020-01-02T15:04:05Z"}`
	tel := MapKernelJSONToTelemetry([]byte(raw), "e", "h", "linux", nil)
	if tel == nil || tel.Fork == nil || tel.Fork.ChildPID != 2 || !tel.Fork.IsThread {
		t.Fatalf("expected fork thread clone, got %+v", tel.Fork)
	}
}

func TestMapKernelJSONToTelemetry_Module(t *testing.T) {
	raw := `{"type":"module","timestamp":"2020-01-02T15:04:05Z"}`
	tel := MapKernelJSONToTelemetry([]byte(raw), "e", "h", "linux", nil)
	if tel == nil || tel.Process == nil || tel.Process.ProcessName != "module" {
		t.Fatalf("expected module shim process, got %+v", tel)
	}
}

func TestParseKernelJSONTime(t *testing.T) {
	raw := map[string]interface{}{"timestamp": "2021-03-04T12:00:00.123456789Z"}
	ts := parseKernelJSONTime(raw)
	if ts.Year() != 2021 || ts.Month() != time.March {
		t.Fatalf("time: %v", ts)
	}
}

func TestMapKernelJSON_ProcessUIDResolvesUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX uid lookup")
	}
	users := NewUsernameCache()
	raw := `{"type":"process","pid":1,"ppid":0,"uid":0,"path":"/sbin/init","timestamp":"2020-01-02T15:04:05Z"}`
	tel := MapKernelJSONToTelemetry([]byte(raw), "e", "h", "linux", users)
	if tel == nil || tel.Process == nil {
		t.Fatal("expected process")
	}
	if tel.Process.User == "" {
		t.Fatal("expected User from uid lookup")
	}
	if u2 := users.Lookup("0"); u2 != tel.Process.User {
		t.Fatalf("cache mismatch %q vs %q", tel.Process.User, u2)
	}
}
