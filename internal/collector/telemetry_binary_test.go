package collector

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func sampleProcessTelemetry() *Telemetry {
	return &Telemetry{
		Process: &schema.ProcessEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventProcess,
				EndpointID:    "endpoint-abc123",
				Hostname:      "host.example.com",
				OS:            "linux",
				Timestamp:     time.Unix(1_700_000_000, 0).UTC(),
			},
			PID:         12345,
			PPID:        1,
			ProcessName: "curl",
			ProcessPath: "/usr/bin/curl",
			CommandLine: "curl -fsSL https://example.com/install.sh -o /tmp/installer",
			User:        "alice",
			Hashes:      []string{"sha256:" + strings.Repeat("0", 64)},
		},
	}
}

func sampleFileTelemetry() *Telemetry {
	return &Telemetry{
		File: &schema.FileEvent{
			BaseEvent: schema.BaseEvent{
				SchemaVersion: schema.SchemaVersionV1,
				EventType:     schema.EventFile,
				EndpointID:    "endpoint-abc123",
				Hostname:      "host.example.com",
				OS:            "linux",
				Timestamp:     time.Unix(1_700_000_000, 0).UTC(),
			},
			Path:         "/var/log/syslog",
			Operation:    "write",
			ActorPID:     12345,
			BytesWritten: 4096,
			Hash:         strings.Repeat("a", 64),
		},
	}
}

func TestTelemetryBinaryRoundTrip(t *testing.T) {
	for name, src := range map[string]*Telemetry{
		"process": sampleProcessTelemetry(),
		"file":    sampleFileTelemetry(),
	} {
		t.Run(name, func(t *testing.T) {
			b, err := MarshalTelemetryBinary(src)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !IsTelemetryBinaryRecord(b) {
				t.Fatalf("magic prefix missing in %x", b[:min(8, len(b))])
			}
			got, err := UnmarshalTelemetryBinary(b)
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			switch name {
			case "process":
				if got.Process == nil || got.Process.PID != src.Process.PID ||
					got.Process.CommandLine != src.Process.CommandLine {
					t.Fatalf("process payload mismatch: %+v", got.Process)
				}
			case "file":
				if got.File == nil || got.File.Path != src.File.Path ||
					got.File.BytesWritten != src.File.BytesWritten {
					t.Fatalf("file payload mismatch: %+v", got.File)
				}
			}
		})
	}
}

func TestTelemetryBinaryRejectsJSON(t *testing.T) {
	// A JSON line starts with '{'; the magic probe must reject it
	// so the queue reader knows to dispatch to the JSON path.
	if IsTelemetryBinaryRecord([]byte(`{"kind":"process"}`)) {
		t.Fatal("JSON record mis-identified as binary")
	}
}

func TestTelemetryBinaryEmpty(t *testing.T) {
	b, err := MarshalTelemetryBinary(nil)
	if err != nil || b != nil {
		t.Fatalf("nil telemetry should yield (nil,nil), got %v/%v", b, err)
	}
	b, err = MarshalTelemetryBinary(&Telemetry{})
	if err != nil || b != nil {
		t.Fatalf("empty telemetry should yield (nil,nil), got %v/%v", b, err)
	}
}

func BenchmarkMarshalTelemetryLine_JSON(b *testing.B) {
	t := sampleProcessTelemetry()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := MarshalTelemetryLine(t)
		if err != nil || len(out) == 0 {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalTelemetryBinary(b *testing.B) {
	t := sampleProcessTelemetry()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := MarshalTelemetryBinary(t)
		if err != nil || len(out) == 0 {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoundTripBinary(b *testing.B) {
	t := sampleProcessTelemetry()
	buf, err := MarshalTelemetryBinary(t)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := UnmarshalTelemetryBinary(buf)
		if err != nil || out == nil {
			b.Fatal(err)
		}
	}
}

// guard against gob silently emitting empty output if the encoder
// closure shape ever regresses.
func TestTelemetryBinaryNotEmpty(t *testing.T) {
	src := sampleProcessTelemetry()
	b, err := MarshalTelemetryBinary(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 32 {
		t.Fatalf("binary record suspiciously small: %d bytes", len(b))
	}
	if bytes.Count(b, []byte{0}) == len(b) {
		t.Fatal("binary record is all zeros")
	}
}
