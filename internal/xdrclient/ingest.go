package xdrclient

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	telemetryv1 "github.com/razatechofficial/xdr/api/proto/telemetry/v1"
)

// IngestClient streams OCSF JSON lines as TelemetryBatch payloads.
type IngestClient struct {
	hosts      []string
	agentID    string
	tenantID   string
	store      Store
	insecure   bool
	log        *slog.Logger
	heartbeat  time.Duration

	mu       sync.Mutex
	conn     *grpc.ClientConn
	stream   telemetryv1.TelemetryService_StreamTelemetryClient
	seq      atomic.Int64
	hostIdx  int
}

// NewIngestClient builds a client. Call Connect before Send, or Send will connect lazily.
func NewIngestClient(hosts []string, agentID, tenantID string, store Store, insecureSkip bool, heartbeatSec int32, log *slog.Logger) *IngestClient {
	if log == nil {
		log = slog.Default()
	}
	hb := 30 * time.Second
	if heartbeatSec > 0 {
		hb = time.Duration(heartbeatSec) * time.Second
	}
	return &IngestClient{
		hosts:     append([]string(nil), hosts...),
		agentID:   agentID,
		tenantID:  tenantID,
		store:     store,
		insecure:  insecureSkip,
		log:       log,
		heartbeat: hb,
	}
}

// Send implements a line sender for TelemetryRelay: one OCSF JSON line per batch.
func (c *IngestClient) Send(ctx context.Context, line []byte) error {
	if c == nil || len(line) == 0 {
		return nil
	}
	if err := c.ensureStream(ctx); err != nil {
		return err
	}
	seq := c.seq.Add(1)
	c.mu.Lock()
	stream := c.stream
	c.mu.Unlock()
	if stream == nil {
		return fmt.Errorf("ingest stream not connected")
	}
	if err := stream.Send(&telemetryv1.TelemetryBatch{
		AgentId:  c.agentID,
		TenantId: c.tenantID,
		Sequence: seq,
		Payload:  line,
	}); err != nil {
		c.resetStream()
		return err
	}
	ack, err := stream.Recv()
	if err != nil {
		c.resetStream()
		return err
	}
	if !ack.GetAccepted() {
		return fmt.Errorf("ingest rejected seq=%d: %s", ack.GetSequence(), ack.GetMessage())
	}
	return nil
}

// Close tears down the gRPC connection.
func (c *IngestClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stream = nil
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// RunHeartbeat sends empty batches when idle so ingest last_seen stays fresh.
func (c *IngestClient) RunHeartbeat(ctx context.Context) {
	t := time.NewTicker(c.heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.Send(ctx, []byte(`{"class_uid":0,"type_uid":0,"activity_id":0,"severity":{"status":"heartbeat"}}`))
		}
	}
}

func (c *IngestClient) ensureStream(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		return nil
	}
	if len(c.hosts) == 0 {
		return fmt.Errorf("no ingest hosts")
	}
	var lastErr error
	for i := 0; i < len(c.hosts); i++ {
		idx := (c.hostIdx + i) % len(c.hosts)
		host := c.hosts[idx]
		conn, stream, err := c.dial(ctx, host)
		if err != nil {
			lastErr = err
			c.log.Warn("ingest dial failed", "host", host, "error", err)
			continue
		}
		c.conn = conn
		c.stream = stream
		c.hostIdx = idx
		c.log.Info("ingest stream connected", "host", host)
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all ingest hosts failed")
	}
	return lastErr
}

func (c *IngestClient) dial(ctx context.Context, host string) (*grpc.ClientConn, telemetryv1.TelemetryService_StreamTelemetryClient, error) {
	_ = ctx
	var opts []grpc.DialOption
	if c.insecure || !c.store.HasCredentials() {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsCfg, err := LoadClientTLS(c.store.CertPath(), c.store.KeyPath(), c.store.CAPath())
		if err != nil {
			return nil, nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}
	conn, err := grpc.NewClient(host, opts...)
	if err != nil {
		return nil, nil, err
	}
	client := telemetryv1.NewTelemetryServiceClient(conn)
	stream, err := client.StreamTelemetry(context.Background())
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, stream, nil
}

func (c *IngestClient) resetStream() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stream = nil
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	if len(c.hosts) > 0 {
		c.hostIdx = (c.hostIdx + 1) % len(c.hosts)
	}
}