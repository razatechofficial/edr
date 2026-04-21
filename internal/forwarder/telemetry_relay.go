package forwarder

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/razatechofficial/edr/internal/telemetryqueue"
)

// TelemetryRelay POSTs JSON telemetry lines upstream and spills to disk on failure.
type TelemetryRelay struct {
	endpoint string
	client   *http.Client
	q        *telemetryqueue.Manager
	log      *slog.Logger
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

// TrySend POSTs one telemetry JSON line; on error the caller may Enqueue.
func (r *TelemetryRelay) TrySend(ctx context.Context, line []byte) error {
	if r == nil || len(line) == 0 {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(line))
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
func (r *TelemetryRelay) Run(ctx context.Context) {
	if r == nil || r.q == nil {
		return
	}
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
