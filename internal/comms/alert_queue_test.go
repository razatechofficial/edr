package comms

import (
	"testing"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestAlertQueueEnqueueDrain(t *testing.T) {
	t.Parallel()
	q := NewAlertQueue(t.TempDir())
	al := schema.Alert{AlertID: "a1", RuleID: "R1", Title: "test", Severity: schema.SeverityHigh}
	if err := q.Enqueue(al); err != nil {
		t.Fatal(err)
	}
	got, err := q.Drain(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].AlertID != "a1" {
		t.Fatalf("drain = %+v", got)
	}
	again, err := q.Drain(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("expected empty queue, got %+v", again)
	}
}

func TestAlertQueuePendingCount(t *testing.T) {
	t.Parallel()
	q := NewAlertQueue(t.TempDir())
	count, err := q.PendingCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("count = %d", count)
	}
	if err := q.Enqueue(schema.Alert{AlertID: "a1"}); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(schema.Alert{AlertID: "a2"}); err != nil {
		t.Fatal(err)
	}
	count, err = q.PendingCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("count = %d want 2", count)
	}
}
