package collectors

import (
	"context"
	"math"
	"strconv"
	"strings"
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
	SuspectedDGA bool          `json:"suspected_dga"`
	TunnelScore  float64       `json:"tunnel_score"`
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
		SuspectedDGA: looksLikeDGA(queryName),
		TunnelScore:  dnsTunnelScore(queryName, queryTypeNum, numAnswers),
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

func looksLikeDGA(q string) bool {
	host := strings.ToLower(strings.TrimSuffix(q, "."))
	if host == "" {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) == 0 || labels[0] == "" {
		return false
	}
	l := labels[0]
	if len(l) < 12 {
		return false
	}
	var digits int
	for i := 0; i < len(l); i++ {
		if l[i] >= '0' && l[i] <= '9' {
			digits++
		}
	}
	return shannon(l) > 3.6 || float64(digits)/float64(len(l)) > 0.35
}

func dnsTunnelScore(query string, qtype uint16, answers uint16) float64 {
	host := strings.TrimSuffix(query, ".")
	score := 0.0
	if len(host) > 55 {
		score += 0.35
	}
	if strings.Count(host, ".") >= 4 {
		score += 0.25
	}
	if qtype == 16 || qtype == 255 {
		score += 0.25
	}
	if answers == 0 {
		score += 0.15
	}
	if score > 1 {
		score = 1
	}
	return score
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[byte]float64, len(s))
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	l := float64(len(s))
	for _, c := range freq {
		p := c / l
		h -= p * math.Log2(p)
	}
	return h
}
