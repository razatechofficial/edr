package forensics

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// TimelineEvent represents a single point on a forensic timeline.
type TimelineEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// Timeline is an ordered sequence of forensic events.
type Timeline struct {
	Events []TimelineEvent `json:"events"`
}

// TimelineBuilder aggregates events from multiple sources into a unified,
// chronologically sorted forensic timeline.
type TimelineBuilder struct {
	mu     sync.Mutex
	events []TimelineEvent
}

// NewTimelineBuilder creates an empty builder.
func NewTimelineBuilder() *TimelineBuilder {
	return &TimelineBuilder{}
}

// AddEvent appends a timestamped event from the named source. The optional
// data map carries arbitrary key-value evidence associated with the event.
func (tb *TimelineBuilder) AddEvent(ts time.Time, source, description string, data map[string]interface{}) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.events = append(tb.events, TimelineEvent{
		Timestamp:   ts.UTC(),
		Source:      source,
		Description: description,
		Data:        data,
	})
}

// Build returns a finalized Timeline with all events sorted by timestamp.
func (tb *TimelineBuilder) Build() *Timeline {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	sorted := make([]TimelineEvent, len(tb.events))
	copy(sorted, tb.events)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})
	return &Timeline{Events: sorted}
}

// Export serializes the timeline in the given format. Supported formats
// are "json" (pretty-printed) and "csv".
func (tb *TimelineBuilder) Export(format string) ([]byte, error) {
	tl := tb.Build()
	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(tl, "", "  ")
	case "csv":
		return exportCSV(tl)
	default:
		return nil, fmt.Errorf("timeline: unsupported format %q (use json or csv)", format)
	}
}

func exportCSV(tl *Timeline) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"timestamp", "source", "description", "data"}); err != nil {
		return nil, err
	}
	for _, e := range tl.Events {
		dataJSON, _ := json.Marshal(e.Data)
		if err := w.Write([]string{
			e.Timestamp.Format(time.RFC3339Nano),
			e.Source,
			e.Description,
			string(dataJSON),
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}
