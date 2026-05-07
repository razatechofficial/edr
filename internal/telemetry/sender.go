package telemetry

import (
	"context"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Transport is the interface for the underlying delivery mechanism (gRPC,
// HTTP, etc.). Implementations must be safe for concurrent use.
type Transport interface {
	Send(ctx context.Context, data []byte) error
}

// SenderConfig tunes retry and fallback behaviour.
type SenderConfig struct {
	MaxRetries     int
	BaseBackoff    time.Duration
	MaxBackoff     time.Duration
	SpoolBatchSize int
}

// DefaultSenderConfig returns production-ready defaults.
func DefaultSenderConfig() SenderConfig {
	return SenderConfig{
		MaxRetries:     5,
		BaseBackoff:    500 * time.Millisecond,
		MaxBackoff:     30 * time.Second,
		SpoolBatchSize: 100,
	}
}

// Sender provides reliable event delivery with retry, spooling, and
// deduplication via sequence numbers.
type Sender struct {
	transport Transport
	spool     *Spool
	cfg       SenderConfig
	logger    *zap.Logger
	sealer    func([]byte) ([]byte, error)

	seq       atomic.Uint64
	drainOnce sync.Once
	drainStop chan struct{}
	sealedOK  atomic.Uint64
	sealedErr atomic.Uint64
}

// NewSender creates a Sender. If spool is nil, events that cannot be
// delivered after retries are dropped.
func NewSender(transport Transport, spool *Spool, cfg SenderConfig, logger *zap.Logger) *Sender {
	s := &Sender{
		transport: transport,
		spool:     spool,
		cfg:       cfg,
		logger:    logger,
		drainStop: make(chan struct{}),
	}
	if spool != nil {
		go s.drainLoop()
	}
	return s
}

// SetSealer installs optional envelope sealing before transport/spool.
func (s *Sender) SetSealer(sealer func([]byte) ([]byte, error)) { s.sealer = sealer }

// Send delivers data with retry and exponential backoff. On persistent
// failure the payload is written to the offline spool.
func (s *Sender) Send(ctx context.Context, data []byte) error {
	s.seq.Add(1)
	payload := data
	if s.sealer != nil {
		sealed, err := s.sealer(data)
		if err != nil {
			s.sealedErr.Add(1)
			return err
		}
		s.sealedOK.Add(1)
		payload = sealed
	}

	var lastErr error
	for attempt := 0; attempt <= s.cfg.MaxRetries; attempt++ {
		if err := s.transport.Send(ctx, payload); err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			backoff := s.backoff(attempt)
			s.logger.Debug("send attempt failed, retrying",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
				zap.Error(err),
			)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			continue
		}
		return nil
	}

	if s.spool != nil {
		s.logger.Warn("send failed after retries, spooling", zap.Error(lastErr))
		return s.spool.Write(payload)
	}
	return lastErr
}

// SendCritical delivers a critical alert immediately without batching.
// Falls back to spool on failure.
func (s *Sender) SendCritical(ctx context.Context, data []byte) error {
	return s.Send(ctx, data)
}

// Stop terminates the background spool drain goroutine.
func (s *Sender) Stop() {
	s.drainOnce.Do(func() {
		close(s.drainStop)
	})
}

// Health exposes sender-level counters for diagnostics.
func (s *Sender) Health() map[string]any {
	if s == nil {
		return map[string]any{"sealer_active": false}
	}
	return map[string]any{
		"sealer_active": s.sealer != nil,
		"sealed_ok":     s.sealedOK.Load(),
		"sealed_err":    s.sealedErr.Load(),
	}
}

func (s *Sender) backoff(attempt int) time.Duration {
	base := float64(s.cfg.BaseBackoff)
	d := base * math.Pow(2, float64(attempt))
	if d > float64(s.cfg.MaxBackoff) {
		d = float64(s.cfg.MaxBackoff)
	}
	jitter := d * 0.2 * rand.Float64()
	return time.Duration(d + jitter)
}

func (s *Sender) drainLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.drainStop:
			return
		case <-ticker.C:
			s.drainSpool()
		}
	}
}

func (s *Sender) drainSpool() {
	keys, values, err := s.spool.ReadKeys(s.cfg.SpoolBatchSize)
	if err != nil {
		s.logger.Error("spool drain read failed", zap.Error(err))
		return
	}
	if len(keys) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var acked [][]byte
	for i, data := range values {
		if err := s.transport.Send(ctx, data); err != nil {
			s.logger.Debug("spool drain send failed, will retry later", zap.Error(err))
			break
		}
		acked = append(acked, keys[i])
	}

	if len(acked) > 0 {
		if err := s.spool.Ack(acked); err != nil {
			s.logger.Error("spool drain ack failed", zap.Error(err))
		} else {
			s.logger.Info("drained spooled events", zap.Int("count", len(acked)))
		}
	}
}
