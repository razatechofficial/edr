package baseline

import (
	"fmt"
	"sync"

	"go.uber.org/zap"
)

const (
	catNetDestIP      = "net.dest_ip"
	catNetDestPort    = "net.dest_port"
	catNetBandwidth   = "net.bandwidth"
	catNetConnFreq    = "net.conn_freq"
	catNetDNSQuery    = "net.dns_query"
)

// NetworkObservation captures a single network event for baseline learning.
type NetworkObservation struct {
	SourceIP    string
	DestIP      string
	DestPort    int
	Protocol    string
	BytesSent   float64
	Domain      string
	ProcessName string
}

// NetworkBaseline tracks normal network behaviour including destination IPs,
// ports, bandwidth patterns, connection frequency, and DNS query patterns.
type NetworkBaseline struct {
	engine *BaselineEngine
	logger *zap.Logger

	mu            sync.RWMutex
	destIPs       map[string]int // ip -> count
	destPorts     map[int]int    // port -> count
	dnsQueries    map[string]int // domain -> count
	processConns  map[string]int // process -> conn count
}

// NewNetworkBaseline creates a network baseline analyser backed by the given engine.
func NewNetworkBaseline(engine *BaselineEngine, logger *zap.Logger) *NetworkBaseline {
	return &NetworkBaseline{
		engine:       engine,
		logger:       logger,
		destIPs:      make(map[string]int),
		destPorts:    make(map[int]int),
		dnsQueries:   make(map[string]int),
		processConns: make(map[string]int),
	}
}

// Observe records a network event for baseline learning.
func (nb *NetworkBaseline) Observe(obs NetworkObservation) {
	nb.mu.Lock()
	defer nb.mu.Unlock()

	if obs.DestIP != "" {
		nb.destIPs[obs.DestIP]++
		nb.engine.AddObservation(catNetDestIP, obs.DestIP, 1)
	}

	if obs.DestPort > 0 {
		nb.destPorts[obs.DestPort]++
		nb.engine.AddObservation(catNetDestPort, fmt.Sprintf("%d", obs.DestPort), 1)
	}

	if obs.BytesSent > 0 {
		key := obs.DestIP
		if key == "" {
			key = "_total"
		}
		nb.engine.AddObservation(catNetBandwidth, key, obs.BytesSent)
	}

	if obs.ProcessName != "" {
		nb.processConns[obs.ProcessName]++
		nb.engine.AddObservation(catNetConnFreq, obs.ProcessName, float64(nb.processConns[obs.ProcessName]))
	}

	if obs.Domain != "" {
		nb.dnsQueries[obs.Domain]++
		nb.engine.AddObservation(catNetDNSQuery, obs.Domain, 1)
	}
}

// CheckDestIP returns true if the destination IP has never been observed.
func (nb *NetworkBaseline) CheckDestIP(ip string) bool {
	if nb.engine.IsLearning() {
		return false
	}

	nb.mu.RLock()
	defer nb.mu.RUnlock()
	_, seen := nb.destIPs[ip]
	return !seen
}

// CheckDestPort returns true if the destination port has never been observed.
func (nb *NetworkBaseline) CheckDestPort(port int) bool {
	if nb.engine.IsLearning() {
		return false
	}

	nb.mu.RLock()
	defer nb.mu.RUnlock()
	_, seen := nb.destPorts[port]
	return !seen
}

// CheckBandwidth returns true and a deviation score if bandwidth to the
// destination is anomalous.
func (nb *NetworkBaseline) CheckBandwidth(dest string, bytes float64) (bool, float64) {
	return nb.engine.IsAnomaly(catNetBandwidth, dest, bytes)
}

// CheckConnFrequency returns true if the process's connection frequency is anomalous.
func (nb *NetworkBaseline) CheckConnFrequency(processName string, connCount float64) (bool, float64) {
	return nb.engine.IsAnomaly(catNetConnFreq, processName, connCount)
}

// CheckDNSQuery returns true if the domain has never been queried before.
func (nb *NetworkBaseline) CheckDNSQuery(domain string) bool {
	if nb.engine.IsLearning() {
		return false
	}

	nb.mu.RLock()
	defer nb.mu.RUnlock()
	_, seen := nb.dnsQueries[domain]
	return !seen
}
