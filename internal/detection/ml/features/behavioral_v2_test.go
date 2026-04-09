package features

import (
	"testing"
	"time"
)

type mockEvent struct {
	eventType string
	category  string
	privilege string
	ts        time.Time
}

func (m mockEvent) GetType() string           { return m.eventType }
func (m mockEvent) GetCategory() string       { return m.category }
func (m mockEvent) GetPrivilegeLevel() string { return m.privilege }
func (m mockEvent) GetTimestamp() time.Time   { return m.ts }

func TestTransformerExtractor_EmptyEvents(t *testing.T) {
	ext := NewTransformerFeatureExtractor(0)
	result := ext.Extract(nil)
	if len(result) != FeaturesPerEvent {
		t.Fatalf("empty input should return 1 zero-padded event vector, got len=%d", len(result))
	}
	for i, v := range result {
		if v != 0 {
			t.Fatalf("expected all zeros for empty input, got non-zero at [%d]=%f", i, v)
		}
	}
}

func TestTransformerExtractor_SingleEvent(t *testing.T) {
	ext := NewTransformerFeatureExtractor(100)
	events := []interface{}{
		mockEvent{
			eventType: "process_create",
			category:  "shell",
			privilege: "elevated",
			ts:        time.Date(2026, 1, 15, 14, 30, 0, 0, time.UTC),
		},
	}
	result := ext.Extract(events)
	if len(result) != FeaturesPerEvent {
		t.Fatalf("single event should produce %d features, got %d", FeaturesPerEvent, len(result))
	}
	if result[0] != 1.0 {
		t.Error("process_create should set index 0 to 1.0")
	}
	privOffset := numEventSubtypes + numProcessCats + 1
	if result[privOffset] != 1.0 {
		t.Error("elevated privilege should be set")
	}
}

func TestTransformerExtractor_MultipleEvents(t *testing.T) {
	ext := NewTransformerFeatureExtractor(100)
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	events := []interface{}{
		mockEvent{eventType: "process_create", category: "other", privilege: "standard", ts: ts},
		mockEvent{eventType: "file_write", category: "other", privilege: "standard", ts: ts.Add(5 * time.Second)},
		mockEvent{eventType: "network_connect", category: "other", privilege: "system", ts: ts.Add(10 * time.Second)},
	}
	result := ext.Extract(events)
	if len(result) != 3*FeaturesPerEvent {
		t.Fatalf("3 events should produce %d features, got %d", 3*FeaturesPerEvent, len(result))
	}
}

func TestTransformerExtractor_MaxSeqTruncation(t *testing.T) {
	ext := NewTransformerFeatureExtractor(5)
	events := make([]interface{}, 20)
	for i := range events {
		events[i] = mockEvent{eventType: "process_create", privilege: "standard"}
	}
	result := ext.Extract(events)
	if len(result) != 5*FeaturesPerEvent {
		t.Fatalf("should truncate to 5 events, got len=%d (expected %d)", len(result), 5*FeaturesPerEvent)
	}
}

func TestTransformerExtractor_SequenceLength(t *testing.T) {
	ext := NewTransformerFeatureExtractor(10)
	events := make([]interface{}, 15)
	for i := range events {
		events[i] = mockEvent{}
	}
	if ext.SequenceLength(events) != 10 {
		t.Errorf("expected capped at 10, got %d", ext.SequenceLength(events))
	}
	if ext.SequenceLength(events[:3]) != 3 {
		t.Errorf("expected 3 for 3 events, got %d", ext.SequenceLength(events[:3]))
	}
}

func TestTransformerExtractor_DefaultMaxSeq(t *testing.T) {
	ext := NewTransformerFeatureExtractor(0)
	if ext.maxSeq != TransformerMaxSeq {
		t.Errorf("0 should default to %d, got %d", TransformerMaxSeq, ext.maxSeq)
	}
	ext2 := NewTransformerFeatureExtractor(999999)
	if ext2.maxSeq != TransformerMaxSeq {
		t.Errorf("oversized should cap to %d, got %d", TransformerMaxSeq, ext2.maxSeq)
	}
}

func TestClassifyEvent_Defaults(t *testing.T) {
	et, cat, priv, ts := classifyEvent("not-a-real-event")
	if et != "process_create" {
		t.Errorf("default event type should be process_create, got %s", et)
	}
	if cat != "other" {
		t.Errorf("default category should be other, got %s", cat)
	}
	if priv != "standard" {
		t.Errorf("default privilege should be standard, got %s", priv)
	}
	if !ts.IsZero() {
		t.Error("default timestamp should be zero")
	}
}

func TestClassifyEvent_MockEvent(t *testing.T) {
	now := time.Now()
	evt := mockEvent{eventType: "file_delete", category: "browser", privilege: "system", ts: now}
	et, cat, priv, ts := classifyEvent(evt)
	if et != "file_delete" || cat != "browser" || priv != "system" || !ts.Equal(now) {
		t.Errorf("classifyEvent didn't extract mock values: %s/%s/%s/%v", et, cat, priv, ts)
	}
}
