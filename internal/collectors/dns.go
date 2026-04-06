package collectors

import (
	"context"
	"strconv"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// DNSEvent is emitted when a DNS query is captured from the network stack.
type DNSEvent struct {
	Timestamp    time.Time     `json:"timestamp"`
	PID          uint32        `json:"pid"`
	QueryName    string        `json:"query_name"`
	QueryType    string        `json:"query_type"`
	Answers      []string      `json:"answers,omitempty"`
	ResponseCode string        `json:"response_code"`
	Latency      time.Duration `json:"latency_ns"`
}

// DNSCollector captures and normalizes DNS query events from the kernel.
type DNSCollector struct {
	logger *zap.Logger
	out    chan<- interface{}
}

// NewDNSCollector creates a DNSCollector with the given logger.
func NewDNSCollector(logger *zap.Logger) *DNSCollector {
	return &DNSCollector{logger: logger}
}

// Name returns the collector identifier.
func (c *DNSCollector) Name() string { return "dns" }

// EventTypes returns the coarse event types this collector subscribes to.
func (c *DNSCollector) EventTypes() []events.EventType {
	return []events.EventType{events.EventDNS}
}

// Start stores the output channel.
func (c *DNSCollector) Start(_ context.Context, _ *kernel.RingBuffer, out chan<- interface{}) error {
	c.out = out
	return nil
}

// Stop is a no-op.
func (c *DNSCollector) Stop() error { return nil }

func (c *DNSCollector) processRaw(evt *RawEvent) {
	if evt.Type != EventNetworkDNS {
		return
	}

	r := newPayloadReader(evt.Payload)
	queryName := r.String()
	queryTypeNum := r.Uint16()
	rcodeNum := r.Uint16()
	latencyNs := r.Uint64()
	numAnswers := r.Uint16()

	answers := make([]string, 0, numAnswers)
	for range int(numAnswers) {
		a := r.String()
		if a != "" {
			answers = append(answers, a)
		}
	}
	if r.Err() != nil {
		c.logger.Warn("malformed DNS payload", zap.Error(r.Err()))
		return
	}

	c.emit(&DNSEvent{
		Timestamp:    evt.Timestamp,
		PID:          evt.PID,
		QueryName:    queryName,
		QueryType:    dnsTypeName(queryTypeNum),
		Answers:      answers,
		ResponseCode: dnsRcodeName(rcodeNum),
		Latency:      time.Duration(latencyNs),
	})
}

func (c *DNSCollector) emit(evt interface{}) {
	select {
	case c.out <- evt:
	default:
		c.logger.Warn("output channel full, dropping DNS event")
	}
}

var dnsTypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
	15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}

func dnsTypeName(t uint16) string {
	if name, ok := dnsTypeNames[t]; ok {
		return name
	}
	return "TYPE" + strconv.FormatUint(uint64(t), 10)
}

var dnsRcodeNames = map[uint16]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
	4: "NOTIMP", 5: "REFUSED",
}

func dnsRcodeName(code uint16) string {
	if name, ok := dnsRcodeNames[code]; ok {
		return name
	}
	return "RCODE" + strconv.FormatUint(uint64(code), 10)
}
