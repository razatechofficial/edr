package xdrclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	telemetryv1 "github.com/razatechofficial/xdr/api/proto/telemetry/v1"
)

// CommandHandler executes a remote command pushed from ingest.
type CommandHandler func(ctx context.Context, cmd *telemetryv1.AgentCommand) error

// IngestClient streams OCSF JSON lines and receives ServerFrames (acks + commands).
type IngestClient struct {
	hosts     []string
	agentID   string
	store     Store
	insecure  bool
	log       *slog.Logger
	heartbeat time.Duration
	onCommand CommandHandler

	mu      sync.Mutex
	conn    *grpc.ClientConn
	stream  telemetryv1.TelemetryService_StreamTelemetryClient
	seq     atomic.Int64
	hostIdx int
	pending map[int64]chan *telemetryv1.TelemetryAck
	closed  atomic.Bool
}

// NewIngestClient builds a client. Call Connect before Send, or Send will connect lazily.
func NewIngestClient(hosts []string, agentID string, store Store, insecureSkip bool, heartbeatSec int32, log *slog.Logger) *IngestClient {
	if log == nil {
		log = slog.Default()
	}
	hb := 30 * time.Second
	if heartbeatSec > 0 {
		hb = time.Duration(heartbeatSec) * time.Second
	}
	c := &IngestClient{
		hosts:     append([]string(nil), hosts...),
		agentID:   agentID,
		store:     store,
		insecure:  insecureSkip,
		log:       log,
		heartbeat: hb,
		pending:   make(map[int64]chan *telemetryv1.TelemetryAck),
	}
	if seq := store.LoadIngestSeq(); seq > 0 {
		c.seq.Store(seq)
		log.Info("ingest sequence resumed", "last_seq", seq)
	}
	return c
}

// SetCommandHandler registers the callback for remote AgentCommand frames.
func (c *IngestClient) SetCommandHandler(h CommandHandler) {
	if c == nil {
		return
	}
	c.onCommand = h
}

// Send implements a line sender for TelemetryRelay: one OCSF JSON line per batch.
func (c *IngestClient) Send(ctx context.Context, line []byte) error {
	if c == nil || len(line) == 0 {
		return nil
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if err := c.ensureStream(ctx); err != nil {
			lastErr = err
			if !sleepBackoff(ctx, attempt) {
				return err
			}
			continue
		}
		seq := c.seq.Add(1)
		ackCh := make(chan *telemetryv1.TelemetryAck, 1)
		c.mu.Lock()
		c.pending[seq] = ackCh
		stream := c.stream
		c.mu.Unlock()
		if stream == nil {
			c.failPending(seq)
			lastErr = fmt.Errorf("ingest stream not connected")
			continue
		}
		if err := stream.Send(&telemetryv1.AgentClientFrame{
			Body: &telemetryv1.AgentClientFrame_Batch{
				Batch: &telemetryv1.TelemetryBatch{
					AgentId:  c.agentID,
					Sequence: seq,
					Payload:  line,
				},
			},
		}); err != nil {
			c.failPending(seq)
			c.resetStream()
			lastErr = err
			if !sleepBackoff(ctx, attempt) {
				return err
			}
			continue
		}
		select {
		case <-ctx.Done():
			c.failPending(seq)
			return ctx.Err()
		case ack, ok := <-ackCh:
			if !ok || ack == nil {
				c.resetStream()
				lastErr = fmt.Errorf("ingest stream closed waiting for ack seq=%d", seq)
				continue
			}
			if !ack.GetAccepted() {
				return fmt.Errorf("ingest rejected seq=%d: %s", ack.GetSequence(), ack.GetMessage())
			}
			if seq == 1 || seq%50 == 0 {
				if err := c.store.SaveIngestSeq(seq); err != nil {
					c.log.Debug("persist ingest seq failed", "seq", seq, "error", err)
				}
			}
			return nil
		case <-time.After(45 * time.Second):
			c.failPending(seq)
			c.resetStream()
			lastErr = fmt.Errorf("ingest ack timeout seq=%d", seq)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("ingest send failed")
	}
	return lastErr
}

func (c *IngestClient) failPending(seq int64) {
	c.mu.Lock()
	ch := c.pending[seq]
	delete(c.pending, seq)
	c.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

// Close tears down the gRPC connection.
func (c *IngestClient) Close() error {
	c.closed.Store(true)
	if seq := c.seq.Load(); seq > 0 {
		_ = c.store.SaveIngestSeq(seq)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stream = nil
	for seq, ch := range c.pending {
		close(ch)
		delete(c.pending, seq)
	}
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
	if c.stream != nil {
		c.mu.Unlock()
		return nil
	}
	hosts := append([]string(nil), c.hosts...)
	startIdx := c.hostIdx
	c.mu.Unlock()

	if len(hosts) == 0 {
		return fmt.Errorf("no ingest hosts")
	}
	if !c.insecure && !c.store.HasCredentials() {
		return fmt.Errorf("device credentials required for ingest mTLS")
	}
	var lastErr error
	for i := 0; i < len(hosts); i++ {
		idx := (startIdx + i) % len(hosts)
		host := hosts[idx]
		conn, stream, err := c.dial(ctx, host)
		if err != nil {
			lastErr = err
			c.log.Warn("ingest dial failed", "host", host, "error", err)
			continue
		}
		c.mu.Lock()
		if c.stream != nil {
			c.mu.Unlock()
			_ = conn.Close()
			return nil
		}
		c.conn = conn
		c.stream = stream
		c.hostIdx = idx
		c.mu.Unlock()
		c.log.Info("ingest stream connected", "host", host)
		go c.recvLoop()
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
	if c.insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		c.log.Warn("ingest using insecure transport (insecure_skip_tls=true); client cert not presented")
	} else {
		tlsCfg, err := LoadClientTLSFromStore(c.store)
		if err != nil {
			return nil, nil, err
		}
		tlsCfg = TLSConfigForIngestHost(tlsCfg, host)
		c.log.Info("ingest presenting device certificate via mTLS",
			"host", host,
			"server_name", tlsCfg.ServerName,
			"secure_storage", c.store.BackendName(),
		)
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

func (c *IngestClient) recvLoop() {
	for {
		if c.closed.Load() {
			return
		}
		c.mu.Lock()
		stream := c.stream
		c.mu.Unlock()
		if stream == nil {
			return
		}
		frame, err := stream.Recv()
		if err != nil {
			c.log.Warn("ingest recv ended", "error", err)
			c.resetStream()
			return
		}
		switch body := frame.GetBody().(type) {
		case *telemetryv1.ServerFrame_Ack:
			ack := body.Ack
			c.mu.Lock()
			ch := c.pending[ack.GetSequence()]
			delete(c.pending, ack.GetSequence())
			c.mu.Unlock()
			if ch != nil {
				ch <- ack
				close(ch)
			}
		case *telemetryv1.ServerFrame_Command:
			cmd := body.Command
			if c.onCommand != nil && cmd != nil {
				go func(cmd *telemetryv1.AgentCommand) {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					defer cancel()
					if err := c.onCommand(ctx, cmd); err != nil {
						c.log.Warn("remote command failed",
							"command_id", cmd.GetCommandId(),
							"type", cmd.GetType(),
							"error", err,
						)
						return
					}
					c.log.Info("remote command executed",
						"command_id", cmd.GetCommandId(),
						"type", cmd.GetType(),
					)
				}(cmd)
			}
		case *telemetryv1.ServerFrame_Control:
			ctrl := body.Control
			c.log.Info("ingest stream control",
				"code", ctrl.GetCode().String(),
				"message", ctrl.GetMessage(),
			)
			c.resetStream()
			return
		}
	}
}

func (c *IngestClient) resetStream() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stream = nil
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	for seq, ch := range c.pending {
		close(ch)
		delete(c.pending, seq)
	}
	if len(c.hosts) > 0 {
		c.hostIdx = (c.hostIdx + 1) % len(c.hosts)
	}
}

func sleepBackoff(ctx context.Context, attempt int) bool {
	base := time.Duration(1<<min(attempt, 5)) * time.Second
	jitter := time.Duration(rand.Int63n(int64(base / 2)))
	t := time.NewTimer(base + jitter)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MapRemoteCommandType converts ingest/command type strings to response OpKey strings.
func MapRemoteCommandType(typ string) string {
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case "COMMAND_TYPE_KILL_PROCESS", "KILL_PROCESS", "KILLPROCESS":
		return "kill_process"
	case "COMMAND_TYPE_ISOLATE_HOST", "ISOLATE_HOST", "NETWORK_ISOLATE", "HOST_ISOLATE":
		return "network_isolate"
	case "COMMAND_TYPE_COLLECT_FORENSIC", "COLLECT_FORENSIC", "COLLECT_FORENSICS":
		return "collect_forensics"
	default:
		return strings.ToLower(strings.TrimSpace(typ))
	}
}

// ParseCommandPayload unmarshals JSON command payload into a generic map.
func ParseCommandPayload(raw []byte) map[string]interface{} {
	out := map[string]interface{}{}
	if len(raw) == 0 {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}
