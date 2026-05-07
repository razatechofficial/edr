package forwarder

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/razatechofficial/edr/internal/telemetryqueue"
)

func TestTelemetryRelayEnqueueAndDrainReplay(t *testing.T) {
	dir := t.TempDir()
	m, err := telemetryqueue.NewManager(dir, 500<<20)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		line := fmt.Appendf(nil, `{"i":%d}`, i)
		if err := m.Append(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.RotateActiveSegment(); err != nil {
		t.Fatal(err)
	}
	var got int
	ctx := context.Background()
	if err := m.DrainOldestSegment(ctx, func([]byte) error {
		got++
		return nil
	}, 10_000); err != nil {
		t.Fatal(err)
	}
	if got != 10 {
		t.Fatalf("replay count got %d want 10", got)
	}
}

func TestTelemetryRelayTrySendEnqueue(t *testing.T) {
	dir := t.TempDir()
	m, err := telemetryqueue.NewManager(dir, 500<<20)
	if err != nil {
		t.Fatal(err)
	}
	r := NewTelemetryRelay("http://127.0.0.1:1/", m, slog.Default())
	line := []byte(`{"k":"v"}`)
	if err := r.TrySend(context.Background(), line); err == nil {
		t.Fatal("expected connection error to unreachable port")
	}
	r.Enqueue(line)
	if err := m.RotateActiveSegment(); err != nil {
		t.Fatal(err)
	}
	var drained []string
	_ = m.DrainOldestSegment(context.Background(), func(b []byte) error {
		drained = append(drained, string(b))
		return nil
	}, 10_000)
	if len(drained) != 1 || drained[0] != `{"k":"v"}` {
		t.Fatalf("drained: %#v", drained)
	}
}

func TestTelemetryRelayTrySendAppliesSealer(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		got = b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := NewTelemetryRelay(srv.URL, nil, slog.Default())
	r.SetSealer(func(b []byte) ([]byte, error) { return append([]byte("sealed:"), b...), nil })
	if err := r.TrySend(context.Background(), []byte(`{"x":1}`)); err != nil {
		t.Fatalf("TrySend failed: %v", err)
	}
	if string(got) != `sealed:{"x":1}` {
		t.Fatalf("got payload %q", string(got))
	}
}
