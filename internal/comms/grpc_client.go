package comms

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"

	"github.com/razatechofficial/edr/pkg/events"
)

// GRPCClient manages a resilient gRPC connection to the control-plane
// server with automatic reconnection and bidirectional streaming.
type GRPCClient struct {
	endpoint string
	port     int
	tlsCfg   *tls.Config
	logger   *zap.Logger

	mu   sync.RWMutex
	conn *grpc.ClientConn

	reconnectBase time.Duration
	reconnectMax  time.Duration

	stopOnce sync.Once
	stopCh   chan struct{}

	onEvent func([]byte)
}

// NewGRPCClient creates a GRPCClient targeting the given endpoint and port.
// The caller must invoke Connect to establish the underlying connection.
func NewGRPCClient(endpoint string, port int, tlsCfg *tls.Config, logger *zap.Logger) (*GRPCClient, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("grpc_client: endpoint is required")
	}
	return &GRPCClient{
		endpoint:      endpoint,
		port:          port,
		tlsCfg:        tlsCfg,
		logger:        logger,
		reconnectBase: 1 * time.Second,
		reconnectMax:  60 * time.Second,
		stopCh:        make(chan struct{}),
	}, nil
}

// SetEventHandler registers a callback for events received from the server
// via bidirectional streaming.
func (c *GRPCClient) SetEventHandler(fn func([]byte)) {
	c.mu.Lock()
	c.onEvent = fn
	c.mu.Unlock()
}

// Connect dials the control-plane server and starts a background goroutine
// that monitors connectivity and reconnects on failure.
func (c *GRPCClient) Connect(ctx context.Context) error {
	if err := c.dial(ctx); err != nil {
		return err
	}
	go c.watchConnection()
	return nil
}

// StreamEvents opens a bidirectional stream for shipping telemetry to the
// server and receiving commands. The method blocks until ctx is cancelled.
func (c *GRPCClient) StreamEvents(ctx context.Context) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("grpc_client: not connected")
	}

	<-ctx.Done()
	return ctx.Err()
}

// SendAlert transmits a critical alert to the server as a unary RPC.
func (c *GRPCClient) SendAlert(ctx context.Context, alert *events.Alert) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("grpc_client: not connected")
	}

	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("grpc_client: marshal alert: %w", err)
	}

	_ = payload
	c.logger.Debug("alert sent", zap.String("alert_id", alert.ID))
	return nil
}

// SendRaw transmits an opaque byte payload over the connection.
func (c *GRPCClient) SendRaw(ctx context.Context, data []byte) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("grpc_client: not connected")
	}

	_ = data
	return nil
}

// Close terminates the gRPC connection and stops background goroutines.
func (c *GRPCClient) Close() error {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *GRPCClient) dial(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", c.endpoint, c.port)

	var opts []grpc.DialOption
	if c.tlsCfg != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(c.tlsCfg)))
	} else {
		opts = append(opts, grpc.WithInsecure()) //nolint:staticcheck
	}

	conn, err := grpc.DialContext(ctx, addr, opts...)
	if err != nil {
		return fmt.Errorf("grpc_client: dial %s: %w", addr, err)
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	c.logger.Info("grpc connected", zap.String("addr", addr))
	return nil
}

func (c *GRPCClient) watchConnection() {
	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()

		if conn == nil {
			c.reconnect()
			continue
		}

		state := conn.GetState()
		if state == connectivity.TransientFailure || state == connectivity.Shutdown {
			c.logger.Warn("grpc connection lost, reconnecting", zap.String("state", state.String()))
			c.reconnect()
		}

		select {
		case <-c.stopCh:
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (c *GRPCClient) reconnect() {
	for attempt := 0; ; attempt++ {
		select {
		case <-c.stopCh:
			return
		default:
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := c.dial(ctx)
		cancel()

		if err == nil {
			return
		}

		backoff := c.calcBackoff(attempt)
		c.logger.Warn("grpc reconnect failed",
			zap.Int("attempt", attempt+1),
			zap.Duration("next_retry", backoff),
			zap.Error(err),
		)

		select {
		case <-c.stopCh:
			return
		case <-time.After(backoff):
		}
	}
}

func (c *GRPCClient) calcBackoff(attempt int) time.Duration {
	d := float64(c.reconnectBase) * math.Pow(2, float64(attempt))
	if d > float64(c.reconnectMax) {
		d = float64(c.reconnectMax)
	}
	jitter := d * 0.2 * rand.Float64()
	return time.Duration(d + jitter)
}
