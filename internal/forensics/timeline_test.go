package forensics

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTimelineBuilderSort(t *testing.T) {
	t.Parallel()

	tb := NewTimelineBuilder()
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tb.AddEvent(base.Add(3*time.Hour), "network", "outbound connection", nil)
	tb.AddEvent(base.Add(1*time.Hour), "process", "process exec", nil)
	tb.AddEvent(base.Add(5*time.Hour), "file", "file write", nil)
	tb.AddEvent(base.Add(2*time.Hour), "auth", "login attempt", nil)

	tl := tb.Build()
	if len(tl.Events) != 4 {
		t.Fatalf("events = %d, want 4", len(tl.Events))
	}

	for i := 1; i < len(tl.Events); i++ {
		if tl.Events[i].Timestamp.Before(tl.Events[i-1].Timestamp) {
			t.Errorf("events not sorted: event[%d] (%v) before event[%d] (%v)",
				i, tl.Events[i].Timestamp, i-1, tl.Events[i-1].Timestamp)
		}
	}

	if tl.Events[0].Source != "process" {
		t.Errorf("first event source = %q, want 'process'", tl.Events[0].Source)
	}
	if tl.Events[3].Source != "file" {
		t.Errorf("last event source = %q, want 'file'", tl.Events[3].Source)
	}
}

func TestTimelineExportJSON(t *testing.T) {
	t.Parallel()

	tb := NewTimelineBuilder()
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	tb.AddEvent(ts, "process", "suspicious exec", map[string]interface{}{
		"pid":  1234,
		"user": "root",
	})

	data, err := tb.Export("json")
	if err != nil {
		t.Fatalf("Export JSON: %v", err)
	}

	var tl Timeline
	if err := json.Unmarshal(data, &tl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(tl.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(tl.Events))
	}
	if tl.Events[0].Source != "process" {
		t.Errorf("source = %q, want 'process'", tl.Events[0].Source)
	}
	if tl.Events[0].Description != "suspicious exec" {
		t.Errorf("description = %q, want 'suspicious exec'", tl.Events[0].Description)
	}
	if tl.Events[0].Data["pid"] == nil {
		t.Error("expected data.pid to be set")
	}
}

func TestTimelineExportCSV(t *testing.T) {
	t.Parallel()

	tb := NewTimelineBuilder()
	base := time.Date(2025, 3, 1, 8, 0, 0, 0, time.UTC)

	tb.AddEvent(base, "file", "file created", nil)
	tb.AddEvent(base.Add(time.Minute), "network", "dns query", map[string]interface{}{
		"domain": "evil.com",
	})
	tb.AddEvent(base.Add(2*time.Minute), "process", "child spawned", nil)

	data, err := tb.Export("csv")
	if err != nil {
		t.Fatalf("Export CSV: %v", err)
	}

	reader := csv.NewReader(strings.NewReader(string(data)))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}

	// header + 3 data rows
	if len(records) != 4 {
		t.Fatalf("CSV rows = %d, want 4 (1 header + 3 data)", len(records))
	}
	if records[0][0] != "timestamp" {
		t.Errorf("header[0] = %q, want 'timestamp'", records[0][0])
	}
	if records[0][1] != "source" {
		t.Errorf("header[1] = %q, want 'source'", records[0][1])
	}
	if records[1][1] != "file" {
		t.Errorf("first data row source = %q, want 'file'", records[1][1])
	}
}

func TestTimelineExportUnsupportedFormat(t *testing.T) {
	t.Parallel()
	tb := NewTimelineBuilder()
	tb.AddEvent(time.Now(), "test", "test", nil)

	_, err := tb.Export("xml")
	if err == nil {
		t.Fatal("expected error for unsupported format, got nil")
	}
}
