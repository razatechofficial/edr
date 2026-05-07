package telemetry

import (
	"context"
	"errors"
	"testing"
)

type testTransport struct {
	last []byte
	err  error
}

func (t *testTransport) Send(_ context.Context, data []byte) error {
	t.last = append([]byte(nil), data...)
	return t.err
}

func TestSenderSealerAppliedBeforeTransport(t *testing.T) {
	tr := &testTransport{}
	s := NewSender(tr, nil, DefaultSenderConfig(), nil)
	s.SetSealer(func(b []byte) ([]byte, error) { return append([]byte("sealed:"), b...), nil })
	if err := s.Send(context.Background(), []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if string(tr.last) != "sealed:abc" {
		t.Fatalf("got %q", string(tr.last))
	}
}

func TestSenderSealerErrorBubbles(t *testing.T) {
	tr := &testTransport{}
	s := NewSender(tr, nil, DefaultSenderConfig(), nil)
	s.SetSealer(func([]byte) ([]byte, error) { return nil, errors.New("seal fail") })
	if err := s.Send(context.Background(), []byte("abc")); err == nil {
		t.Fatal("expected error")
	}
	if len(tr.last) != 0 {
		t.Fatal("transport should not be called when sealer fails")
	}
}

