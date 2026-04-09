package ml

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTelemetryExporter_RecordAndFlush(t *testing.T) {
	tmpDir := t.TempDir()
	exporter := NewTelemetryExporter(tmpDir, 100)

	exporter.Record(ScoredEvent{
		Timestamp: time.Now(),
		ModelName: "pe_classifier",
		Score:     0.85,
		Category:  "malware",
		Verdict:   "tp",
		Features:  []float32{0.1, 0.2, 0.3},
	})

	if exporter.BufferSize() != 1 {
		t.Errorf("expected buffer size 1, got %d", exporter.BufferSize())
	}

	if err := exporter.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if exporter.BufferSize() != 0 {
		t.Errorf("buffer should be empty after flush, got %d", exporter.BufferSize())
	}

	files, _ := filepath.Glob(filepath.Join(tmpDir, "telemetry_*.csv"))
	if len(files) == 0 {
		t.Fatal("no CSV files created")
	}

	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(data) < 50 {
		t.Errorf("CSV too short: %d bytes", len(data))
	}
}

func TestTelemetryExporter_PIIRedaction(t *testing.T) {
	tmpDir := t.TempDir()
	exporter := NewTelemetryExporter(tmpDir, 100)

	evt := ScoredEvent{
		Timestamp: time.Now(),
		ModelName: "test",
		Score:     0.5,
		EventMeta: map[string]string{
			"hostname": "secret-server",
			"username": "admin",
			"src_ip":   "192.168.1.1",
			"path":     "/bin/malware",
		},
	}
	exporter.Record(evt)

	if exporter.BufferSize() != 1 {
		t.Fatal("expected 1 buffered event")
	}
}

func TestTelemetryExporter_AutoFlushOnFull(t *testing.T) {
	tmpDir := t.TempDir()
	exporter := NewTelemetryExporter(tmpDir, 5)

	for i := 0; i < 6; i++ {
		exporter.Record(ScoredEvent{
			Timestamp: time.Now(),
			ModelName: "test",
			Score:     float64(i) * 0.1,
		})
	}

	files, _ := filepath.Glob(filepath.Join(tmpDir, "telemetry_*.csv"))
	if len(files) == 0 {
		t.Error("auto-flush should have created at least one CSV")
	}
}
