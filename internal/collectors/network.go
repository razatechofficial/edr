package collectors

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// NetworkConnectEvent is emitted when a process initiates an outbound connection.
type NetworkConnectEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	Protocol  string    `json:"protocol"`
	SrcAddr   string    `json:"src_addr"`
	SrcPort   uint16    `json:"src_port"`
	DstAddr   string    `json:"dst_addr"`
	DstPort   uint16    `json:"dst_port"`
	Direction string    `json:"direction"`
	Domain    string    `json:"domain,omitempty"`
	IsPrivate bool      `json:"is_private"`
	RiskScore float64   `json:"risk_score"`
}

// NetworkAcceptEvent is emitted when a process accepts an inbound connection.
type NetworkAcceptEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	Protocol  string    `json:"protocol"`
	SrcAddr   string    `json:"src_addr"`
	SrcPort   uint16    `json:"src_port"`
	DstAddr   string    `json:"dst_addr"`
	DstPort   uint16    `json:"dst_port"`
	Domain    string    `json:"domain,omitempty"`
}

// NetworkBindEvent is emitted when a process binds a socket to a local address.
type NetworkBindEvent struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	Protocol  string    `json:"protocol"`
	Addr      string    `json:"addr"`
	Port      uint16    `json:"port"`
}

const (
	afINET  = 2
	afINET6 = 10
)

// NetworkCollector handles network connection events, resolving IP addresses
// via reverse DNS and determining protocol from socket type.
type NetworkCollector struct {
	logger   *zap.Logger
	out      chan<- interface{}
	dnsCache sync.Map
}

// NewNetworkCollector creates a NetworkCollector with the given logger.
func NewNetworkCollector(logger *zap.Logger) *NetworkCollector {
	return &NetworkCollector{logger: logger}
}

// Name returns the collector identifier.
func (c *NetworkCollector) Name() string { return "network" }

// EventTypes returns the coarse event types this collector subscribes to.
func (c *NetworkCollector) EventTypes() []events.EventType {
	return []events.EventType{events.EventNetwork}
}

// Start stores the output channel.
func (c *NetworkCollector) Start(_ context.Context, _ *kernel.RingBuffer, out chan<- interface{}) error {
	c.out = out
	return nil
}

// Stop is a no-op.
func (c *NetworkCollector) Stop() error { return nil }

func (c *NetworkCollector) processRaw(evt *RawEvent) {
	switch evt.Type {
	case EventNetworkConnect:
		c.handleConnect(evt)
	case EventNetworkAccept:
		c.handleAccept(evt)
	case EventNetworkBind:
		c.handleBind(evt)
	}
}

func (c *NetworkCollector) handleConnect(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	family := r.Uint8()
	proto := r.Uint8()
	direction := r.Uint8()
	srcAddr := readAddr(r, family)
	srcPort := r.Uint16()
	dstAddr := readAddr(r, family)
	dstPort := r.Uint16()
	if r.Err() != nil {
		c.logger.Warn("malformed network connect payload", zap.Error(r.Err()))
		return
	}

	dir := "outbound"
	if direction == 1 {
		dir = "inbound"
	}

	c.emit(&NetworkConnectEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		Protocol:  protoName(proto),
		SrcAddr:   srcAddr,
		SrcPort:   srcPort,
		DstAddr:   dstAddr,
		DstPort:   dstPort,
		Direction: dir,
		Domain:    c.reverseLookup(dstAddr),
		IsPrivate: isPrivateIP(dstAddr),
		RiskScore: networkRiskScore(dstAddr, dstPort, proto),
	})
}

func (c *NetworkCollector) handleAccept(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	family := r.Uint8()
	proto := r.Uint8()
	srcAddr := readAddr(r, family)
	srcPort := r.Uint16()
	dstAddr := readAddr(r, family)
	dstPort := r.Uint16()
	if r.Err() != nil {
		c.logger.Warn("malformed network accept payload", zap.Error(r.Err()))
		return
	}

	c.emit(&NetworkAcceptEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		Protocol:  protoName(proto),
		SrcAddr:   srcAddr,
		SrcPort:   srcPort,
		DstAddr:   dstAddr,
		DstPort:   dstPort,
		Domain:    c.reverseLookup(srcAddr),
	})
}

func (c *NetworkCollector) handleBind(evt *RawEvent) {
	r := newPayloadReader(evt.Payload)
	family := r.Uint8()
	proto := r.Uint8()
	addr := readAddr(r, family)
	port := r.Uint16()
	if r.Err() != nil {
		c.logger.Warn("malformed network bind payload", zap.Error(r.Err()))
		return
	}

	c.emit(&NetworkBindEvent{
		Timestamp: evt.Timestamp,
		PID:       evt.PID,
		Protocol:  protoName(proto),
		Addr:      addr,
		Port:      port,
	})
}

func (c *NetworkCollector) emit(evt interface{}) {
	select {
	case c.out <- evt:
	default:
		c.logger.Warn("output channel full, dropping network event")
	}
}

func (c *NetworkCollector) reverseLookup(addr string) string {
	if v, ok := c.dnsCache.Load(addr); ok {
		return v.(string)
	}
	names, err := net.LookupAddr(addr)
	if err != nil || len(names) == 0 {
		return ""
	}
	c.dnsCache.Store(addr, names[0])
	return names[0]
}

func readAddr(r *payloadReader, family uint8) string {
	switch family {
	case afINET:
		raw := r.Bytes(4)
		if raw == nil {
			return ""
		}
		return net.IP(raw).String()
	case afINET6:
		raw := r.Bytes(16)
		if raw == nil {
			return ""
		}
		return net.IP(raw).String()
	default:
		return fmt.Sprintf("af:%d", family)
	}
}

func protoName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("proto:%d", proto)
	}
}

func isPrivateIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 10 ||
			(v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) ||
			(v4[0] == 192 && v4[1] == 168) ||
			(v4[0] == 127)
	}
	return ip.IsPrivate() || ip.IsLoopback()
}

func networkRiskScore(dstAddr string, dstPort uint16, proto uint8) float64 {
	score := 0.0
	if !isPrivateIP(dstAddr) {
		score += 0.4
	}
	switch dstPort {
	case 4444, 1337, 6667, 31337:
		score += 0.35
	case 22, 3389:
		score += 0.2
	}
	if proto != 6 && proto != 17 {
		score += 0.2
	}
	if score > 1 {
		score = 1
	}
	return score
}
