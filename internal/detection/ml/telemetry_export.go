package ml

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ScoredEvent captures an ML scoring result alongside analyst feedback.
type ScoredEvent struct {
	Timestamp   time.Time          `json:"timestamp"`
	ModelName   string             `json:"model_name"`
	Score       float64            `json:"score"`
	Category    string             `json:"category"`
	Features    []float32          `json:"features,omitempty"`
	EventMeta   map[string]string  `json:"event_meta,omitempty"`
	Verdict     string             `json:"verdict,omitempty"` // "tp", "fp", "unknown"
}

// TelemetryExporter buffers scored events and exports them for retraining.
type TelemetryExporter struct {
	mu          sync.Mutex
	buffer      []ScoredEvent
	maxBuffer   int
	exportDir   string
	redactRules []RedactRule
}

// RedactRule defines a PII redaction pattern.
type RedactRule struct {
	Field       string
	ReplaceWith string
}

var defaultRedactRules = []RedactRule{
	{Field: "hostname", ReplaceWith: "REDACTED_HOST"},
	{Field: "username", ReplaceWith: "REDACTED_USER"},
	{Field: "src_ip", ReplaceWith: "0.0.0.0"},
	{Field: "dst_ip", ReplaceWith: "0.0.0.0"},
	{Field: "user", ReplaceWith: "REDACTED_USER"},
	{Field: "host", ReplaceWith: "REDACTED_HOST"},
}

// NewTelemetryExporter creates a new exporter that buffers up to maxBuffer
// events before auto-flushing to exportDir.
func NewTelemetryExporter(exportDir string, maxBuffer int) *TelemetryExporter {
	if maxBuffer <= 0 {
		maxBuffer = 10000
	}
	return &TelemetryExporter{
		buffer:      make([]ScoredEvent, 0, maxBuffer),
		maxBuffer:   maxBuffer,
		exportDir:   exportDir,
		redactRules: defaultRedactRules,
	}
}

// Record adds a scored event to the buffer. If the buffer is full, it
// triggers an automatic export.
func (t *TelemetryExporter) Record(evt ScoredEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.redactEvent(&evt)
	t.buffer = append(t.buffer, evt)

	if len(t.buffer) >= t.maxBuffer {
		_ = t.flushLocked()
	}
}

// Flush writes all buffered events to a CSV file in the export directory.
func (t *TelemetryExporter) Flush() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.flushLocked()
}

func (t *TelemetryExporter) flushLocked() error {
	if len(t.buffer) == 0 {
		return nil
	}

	if err := os.MkdirAll(t.exportDir, 0o750); err != nil {
		return fmt.Errorf("telemetry: create export dir: %w", err)
	}

	filename := fmt.Sprintf("telemetry_%s.csv", time.Now().UTC().Format("20060102_150405"))
	path := filepath.Join(t.exportDir, filename)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("telemetry: create file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	header := []string{"timestamp", "model_name", "score", "category", "verdict", "features"}
	if err := w.Write(header); err != nil {
		return fmt.Errorf("telemetry: write header: %w", err)
	}

	for _, evt := range t.buffer {
		featStr := formatFeatures(evt.Features)
		row := []string{
			evt.Timestamp.UTC().Format(time.RFC3339),
			evt.ModelName,
			fmt.Sprintf("%.6f", evt.Score),
			evt.Category,
			evt.Verdict,
			featStr,
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("telemetry: write row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("telemetry: flush csv: %w", err)
	}

	t.buffer = t.buffer[:0]
	return nil
}

// BufferSize returns the current number of buffered events.
func (t *TelemetryExporter) BufferSize() int {
	t.mu.Lock()
	n := len(t.buffer)
	t.mu.Unlock()
	return n
}

func (t *TelemetryExporter) redactEvent(evt *ScoredEvent) {
	if evt.EventMeta == nil {
		return
	}
	for _, rule := range t.redactRules {
		for key := range evt.EventMeta {
			if strings.EqualFold(key, rule.Field) || strings.Contains(strings.ToLower(key), strings.ToLower(rule.Field)) {
				evt.EventMeta[key] = rule.ReplaceWith
			}
		}
	}
}

func formatFeatures(feats []float32) string {
	if len(feats) == 0 {
		return ""
	}
	parts := make([]string, len(feats))
	for i, f := range feats {
		parts[i] = fmt.Sprintf("%.4f", f)
	}
	return strings.Join(parts, ";")
}
