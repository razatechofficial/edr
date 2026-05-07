package forwarder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/internal/transport"
	"github.com/segmentio/kafka-go"
)

// Config selects how alerts are delivered to upstream SIEM/XDR.
type Config struct {
	Mode         string
	HTTPEndpoint string
	SyslogAddr   string
	KafkaBrokers []string
	KafkaTopic   string
	RetryMax     int
	SpoolPath    string
	SealEnvelopes bool
	SealKeyPath   string
	SealKeyID     string
}

// Forwarder delivers alerts upstream.
type Forwarder interface {
	Send(alert schema.Alert) error
}

// Drainer replays spooled alerts (when retry wrapper is used).
type Drainer interface {
	DrainPending() error
}

// New builds a forwarder from config. Returns optional Drainer for spool replay.
func New(cfg Config, logger *slog.Logger) (Forwarder, Drainer, error) {
	if cfg.RetryMax <= 0 {
		cfg.RetryMax = 3
	}
	if cfg.SpoolPath == "" {
		cfg.SpoolPath = "./alerts/forward_spool.jsonl"
	}

	var sealFn func([]byte) ([]byte, error)
	if cfg.SealEnvelopes && strings.TrimSpace(cfg.SealKeyPath) != "" {
		fn, err := transport.AESGCMSealer(cfg.SealKeyPath, cfg.SealKeyID)
		if err != nil {
			return nil, nil, fmt.Errorf("forwarder seal: %w", err)
		}
		sealFn = fn
	}

	var inner Forwarder
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "http", "":
		if cfg.HTTPEndpoint == "" {
			return nil, nil, errors.New("http forwarder: endpoint required")
		}
		inner = &httpForwarder{endpoint: cfg.HTTPEndpoint, cli: &http.Client{Timeout: 15 * time.Second}, seal: sealFn}
	case "syslog":
		addr := cfg.SyslogAddr
		if addr == "" {
			return nil, nil, errors.New("syslog forwarder: syslog_addr required")
		}
		inner = &syslogForwarder{addr: addr, logger: logger, seal: sealFn}
	case "kafka":
		if len(cfg.KafkaBrokers) == 0 || cfg.KafkaTopic == "" {
			return nil, nil, errors.New("kafka forwarder: kafka_brokers and kafka_topic required")
		}
		w := &kafka.Writer{
			Addr:     kafka.TCP(cfg.KafkaBrokers...),
			Topic:    cfg.KafkaTopic,
			Balancer: &kafka.LeastBytes{},
		}
		inner = &kafkaForwarder{w: w, seal: sealFn}
	default:
		return nil, nil, fmt.Errorf("unsupported forwarder mode: %s", cfg.Mode)
	}

	rf := &retrySpoolForwarder{
		inner:  inner,
		cfg:    cfg,
		logger: logger,
	}
	return rf, rf, nil
}

type httpForwarder struct {
	endpoint string
	cli      *http.Client
	seal     func([]byte) ([]byte, error)
}

func (h *httpForwarder) Send(alert schema.Alert) error {
	body, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	if h.seal != nil {
		body, err = h.seal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequest(http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return errors.New("forward failed with non-2xx status")
	}
	return nil
}

type syslogForwarder struct {
	addr   string
	logger *slog.Logger
	seal   func([]byte) ([]byte, error)
}

func (s *syslogForwarder) Send(alert schema.Alert) error {
	b, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	if s.seal != nil {
		b, err = s.seal(b)
		if err != nil {
			return err
		}
	}
	conn, err := net.Dial("udp", s.addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// RFC5424-ish: facility 16 (local0), severity 6 (info)
	msg := fmt.Sprintf("<134>1 %s - edr - - - %s", time.Now().UTC().Format(time.RFC3339), string(b))
	_, err = conn.Write([]byte(msg))
	return err
}

type kafkaForwarder struct {
	w    *kafka.Writer
	seal func([]byte) ([]byte, error)
}

func (k *kafkaForwarder) Send(alert schema.Alert) error {
	b, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	if k.seal != nil {
		b, err = k.seal(b)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return k.w.WriteMessages(ctx, kafka.Message{Value: b})
}

type retrySpoolForwarder struct {
	inner  Forwarder
	cfg    Config
	logger *slog.Logger
}

func (r *retrySpoolForwarder) Send(alert schema.Alert) error {
	var last error
	for i := 0; i < r.cfg.RetryMax; i++ {
		if err := r.inner.Send(alert); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
	}
	if r.cfg.SpoolPath != "" {
		if err := AppendSpool(r.cfg.SpoolPath, alert); err != nil {
			return err
		}
		r.logger.Warn("forwarder spooled alert after retries", "error", last)
		return nil
	}
	return last
}

func (r *retrySpoolForwarder) DrainPending() error {
	if r.cfg.SpoolPath == "" {
		return nil
	}
	return DrainSpool(r.cfg.SpoolPath, func(a schema.Alert) error {
		return r.inner.Send(a)
	})
}
