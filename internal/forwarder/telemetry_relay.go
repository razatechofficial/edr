package forwarder

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/razatechofficial/edr/internal/telemetryqueue"
)

// LineSender sends one telemetry JSON line upstream (HTTP or gRPC).
type LineSender interface {
	Send(ctx context.Context, line []byte) error
}

// TelemetryRelay POSTs JSON telemetry lines upstream and spills to disk on failure.
type TelemetryRelay struct {
	endpoint string
	client   *http.Client
	sender   LineSender
	q        *telemetryqueue.Manager
	log      *slog.Logger
	sealer   func([]byte) ([]byte, error)
	sealedOK atomic.Uint64
	sealedErr atomic.Uint64
}

// NewTelemetryRelay builds a relay. endpoint must be a full URL (e.g. https://host/api/telemetry).
func NewTelemetryRelay(endpoint string, q *telemetryqueue.Manager, log *slog.Logger) *TelemetryRelay {
	if log == nil {
		log = slog.Default()
	}
	return &TelemetryRelay{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 15 * time.Second},
		q:        q,
		log:      log,
	}
}

// NewTelemetryRelayWithSender builds a relay that uses sender instead of HTTP POST.
func NewTelemetryRelayWithSender(sender LineSender, q *telemetryqueue.Manager, log *slog.Logger) *TelemetryRelay {
	if log == nil {
		log = slog.Default()
	}
	return &TelemetryRelay{
		sender: sender,
		client: &http.Client{Timeout: 15 * time.Second},
		q:      q,
		log:    log,
	}
}

// TrySend POSTs one telemetry JSON line; on error the caller may Enqueue.
func (r *TelemetryRelay) TrySend(ctx context.Context, line []byte) error {
	if r == nil || len(line) == 0 {
		return nil
	}
	payload := line
	if r.sealer != nil {
		sealed, err := r.sealer(line)
		if err != nil {
			r.sealedErr.Add(1)
			return err
		}
		r.sealedOK.Add(1)
		payload = sealed
	}
	if r.sender != nil {
		return r.sender.Send(ctx, payload)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return errors.New("telemetry post non-2xx")
	}
	return nil
}

func (r *TelemetryRelay) SetSealer(sealer func([]byte) ([]byte, error)) {
	if r == nil {
		return
	}
	r.sealer = sealer
}

// Enqueue persists a line to the on-disk queue.
func (r *TelemetryRelay) Enqueue(line []byte) {
	if r == nil || r.q == nil {
		return
	}
	if err := r.q.Append(line); err != nil {
		r.log.Error("telemetry queue append failed", "error", err)
	}
}

// Run drains queued segments with backpressure and emits periodic health logs.
// Also starts the queue's background fsync loop (P0-11) so writes survive an
// unclean shutdown bounded by ~1 s.
func (r *TelemetryRelay) Run(ctx context.Context) {
	if r == nil || r.q == nil {
		return
	}
	r.q.Start(ctx)
	defer func() {
		if err := r.q.Close(); err != nil {
			r.log.Debug("telemetry queue close error", "error", err)
		}
	}()
	drainTick := time.NewTicker(2 * time.Second)
	healthTick := time.NewTicker(60 * time.Second)
	defer drainTick.Stop()
	defer healthTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-drainTick.C:
			if err := r.q.DrainOldestSegment(ctx, func(line []byte) error {
				return r.TrySend(ctx, line)
			}, 100); err != nil {
				r.log.Debug("telemetry queue drain paused", "error", err)
			}
		case <-healthTick.C:
			b, err := r.q.HealthJSON()
			if err != nil {
				continue
			}
			r.log.Info("telemetry_queue_health", "payload", string(b))
		}
	}
}
