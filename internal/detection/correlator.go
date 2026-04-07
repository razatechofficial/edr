package detection

import (
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// Detector defines the interface for all behavioral detection modules.
type Detector interface {
	// Name returns the detector's unique identifier.
	Name() string
	// Analyze evaluates an event against behavioral patterns, using the correlator
	// for multi-event context. Returns any generated alerts.
	Analyze(event interface{}, correlator *Correlator) []*events.Alert
	// Reset clears all internal state.
	Reset()
}

// TimeWindow defines correlation window durations.
type TimeWindow time.Duration

const (
	// Window30s is a 30-second correlation window.
	Window30s TimeWindow = TimeWindow(30 * time.Second)
	// Window1m is a 1-minute correlation window.
	Window1m TimeWindow = TimeWindow(time.Minute)
	// Window5m is a 5-minute correlation window.
	Window5m TimeWindow = TimeWindow(5 * time.Minute)
	// Window1h is a 1-hour correlation window.
	Window1h TimeWindow = TimeWindow(time.Hour)
	// Window24h is a 24-hour correlation window.
	Window24h TimeWindow = TimeWindow(24 * time.Hour)
)

const correlatorShardCount = 64

type timedEvent struct {
	event       interface{}
	timestamp   time.Time
	pid         uint32
	user        string
	files       []string
	connections []string
}

type eventShard struct {
	mu     sync.RWMutex
	events []timedEvent
}

// Correlator maintains sliding windows of events indexed by PID and user
// for cross-event behavioral correlation. It uses sharded locks to minimize
// contention under high-throughput event ingestion.
type Correlator struct {
	pidShards  [correlatorShardCount]*eventShard
	userShards [correlatorShardCount]*eventShard
	logger     *zap.Logger
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// NewCorrelator creates a Correlator and starts a background goroutine that
// expires events older than 24 hours every 30 seconds. Call Stop to release it.
func NewCorrelator(logger *zap.Logger) *Correlator {
	c := &Correlator{
		logger: logger,
		stopCh: make(chan struct{}),
	}
	for i := range c.pidShards {
		c.pidShards[i] = &eventShard{}
	}
	for i := range c.userShards {
		c.userShards[i] = &eventShard{}
	}
	c.wg.Add(1)
	go c.cleanupLoop()
	return c
}

// AddEvent indexes an event in all applicable sliding windows.
func (c *Correlator) AddEvent(event interface{}) {
	te := c.extract(event)

	ps := c.pidShards[te.pid%correlatorShardCount]
	ps.mu.Lock()
	ps.events = append(ps.events, te)
	ps.mu.Unlock()

	if te.user != "" {
		us := c.userShards[fnvHash(te.user)%correlatorShardCount]
		us.mu.Lock()
		us.events = append(us.events, te)
		us.mu.Unlock()
	}
}

// GetProcessEvents returns raw events for a PID within the given window.
func (c *Correlator) GetProcessEvents(pid uint32, window TimeWindow) []interface{} {
	shard := c.pidShards[pid%correlatorShardCount]
	cutoff := time.Now().Add(-time.Duration(window))

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	var out []interface{}
	for _, e := range shard.events {
		if e.pid == pid && !e.timestamp.Before(cutoff) {
			out = append(out, e.event)
		}
	}
	return out
}

// GetUserEvents returns raw events for a user within the given window.
func (c *Correlator) GetUserEvents(user string, window TimeWindow) []interface{} {
	shard := c.userShards[fnvHash(user)%correlatorShardCount]
	cutoff := time.Now().Add(-time.Duration(window))

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	var out []interface{}
	for _, e := range shard.events {
		if e.user == user && !e.timestamp.Before(cutoff) {
			out = append(out, e.event)
		}
	}
	return out
}

// GetRecentFiles returns deduplicated file paths touched by a PID within the window.
func (c *Correlator) GetRecentFiles(pid uint32, window TimeWindow) []string {
	shard := c.pidShards[pid%correlatorShardCount]
	cutoff := time.Now().Add(-time.Duration(window))

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	seen := make(map[string]struct{})
	var out []string
	for _, e := range shard.events {
		if e.pid == pid && !e.timestamp.Before(cutoff) {
			for _, f := range e.files {
				if _, dup := seen[f]; !dup {
					seen[f] = struct{}{}
					out = append(out, f)
				}
			}
		}
	}
	return out
}

// GetRecentConnections returns deduplicated network targets for a PID within the window.
func (c *Correlator) GetRecentConnections(pid uint32, window TimeWindow) []string {
	shard := c.pidShards[pid%correlatorShardCount]
	cutoff := time.Now().Add(-time.Duration(window))

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	seen := make(map[string]struct{})
	var out []string
	for _, e := range shard.events {
		if e.pid == pid && !e.timestamp.Before(cutoff) {
			for _, conn := range e.connections {
				if _, dup := seen[conn]; !dup {
					seen[conn] = struct{}{}
					out = append(out, conn)
				}
			}
		}
	}
	return out
}

// ProcessTreeEntry represents a node in the process ancestry chain.
type ProcessTreeEntry struct {
	PID  uint32
	PPID uint32
	Name string
	Path string
	Args string
	User string
}

// GetProcessTree walks up the process ancestry chain for the given PID,
// returning entries from child to root. It searches all shards within the
// given time window for process events to reconstruct the lineage.
func (c *Correlator) GetProcessTree(pid uint32, window TimeWindow) []ProcessTreeEntry {
	cutoff := time.Now().Add(-time.Duration(window))

	procMap := make(map[uint32]ProcessTreeEntry)
	for i := 0; i < correlatorShardCount; i++ {
		shard := c.pidShards[i]
		shard.mu.RLock()
		for _, e := range shard.events {
			if e.timestamp.Before(cutoff) {
				continue
			}
			switch pe := e.event.(type) {
			case *schema.ProcessEvent:
				procMap[uint32(pe.PID)] = ProcessTreeEntry{
					PID: uint32(pe.PID), PPID: uint32(pe.PPID),
					Name: pe.ProcessName, Path: pe.ProcessPath,
					Args: pe.CommandLine, User: pe.User,
				}
			case schema.ProcessEvent:
				procMap[uint32(pe.PID)] = ProcessTreeEntry{
					PID: uint32(pe.PID), PPID: uint32(pe.PPID),
					Name: pe.ProcessName, Path: pe.ProcessPath,
					Args: pe.CommandLine, User: pe.User,
				}
			}
		}
		shard.mu.RUnlock()
	}

	var tree []ProcessTreeEntry
	visited := make(map[uint32]bool)
	current := pid
	for {
		if visited[current] {
			break
		}
		visited[current] = true
		entry, ok := procMap[current]
		if !ok {
			break
		}
		tree = append(tree, entry)
		if entry.PPID == 0 || entry.PPID == current {
			break
		}
		current = entry.PPID
	}
	return tree
}

// GetRecentRegistryChanges returns registry modification descriptions for a
// PID within the given window. Registry events are only collected on Windows;
// on other platforms this returns nil.
func (c *Correlator) GetRecentRegistryChanges(_ uint32, _ TimeWindow) []string {
	return nil
}

// Stop cancels the background cleanup goroutine and blocks until it exits.
func (c *Correlator) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

func (c *Correlator) extract(event interface{}) timedEvent {
	te := timedEvent{event: event, timestamp: time.Now()}

	switch ev := event.(type) {
	case *schema.ProcessEvent:
		te.pid, te.user, te.timestamp = uint32(ev.PID), ev.User, ev.Timestamp
	case schema.ProcessEvent:
		te.pid, te.user, te.timestamp = uint32(ev.PID), ev.User, ev.Timestamp
	case *schema.FileEvent:
		te.pid, te.timestamp = uint32(ev.ActorPID), ev.Timestamp
		te.files = []string{ev.Path}
	case schema.FileEvent:
		te.pid, te.timestamp = uint32(ev.ActorPID), ev.Timestamp
		te.files = []string{ev.Path}
	case *schema.NetworkEvent:
		te.pid, te.timestamp = uint32(ev.PID), ev.Timestamp
		target := fmt.Sprintf("%s:%d", ev.DestIP, ev.DestPt)
		if ev.Domain != "" {
			target = fmt.Sprintf("%s(%s)", target, ev.Domain)
		}
		te.connections = []string{target}
	case schema.NetworkEvent:
		te.pid, te.timestamp = uint32(ev.PID), ev.Timestamp
		target := fmt.Sprintf("%s:%d", ev.DestIP, ev.DestPt)
		if ev.Domain != "" {
			target = fmt.Sprintf("%s(%s)", target, ev.Domain)
		}
		te.connections = []string{target}
	case *schema.AuthEvent:
		te.user, te.timestamp = ev.User, ev.Timestamp
	case schema.AuthEvent:
		te.user, te.timestamp = ev.User, ev.Timestamp
	}
	return te
}

func (c *Correlator) cleanupLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-time.Duration(Window24h))
			for i := 0; i < correlatorShardCount; i++ {
				expireShard(c.pidShards[i], cutoff)
				expireShard(c.userShards[i], cutoff)
			}
		}
	}
}

func expireShard(shard *eventShard, cutoff time.Time) {
	shard.mu.Lock()
	defer shard.mu.Unlock()
	n := 0
	for _, e := range shard.events {
		if !e.timestamp.Before(cutoff) {
			shard.events[n] = e
			n++
		}
	}
	for i := n; i < len(shard.events); i++ {
		shard.events[i] = timedEvent{}
	}
	shard.events = shard.events[:n]
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func fnvHash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func newAlert(ruleID, ruleName, title, desc string, sev events.Severity, mitre []events.MITREAttack, tags []string, raw interface{}) *events.Alert {
	return &events.Alert{
		ID:          uuid.New().String(),
		RuleID:      ruleID,
		RuleName:    ruleName,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Timestamp:   time.Now().UTC(),
		MITRE:       mitre,
		Tags:        tags,
		RawEvent:    raw,
	}
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var ent float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Event field extractors – handle both pointer and value schema types.
// ---------------------------------------------------------------------------

func extractPID(event interface{}) uint32 {
	switch ev := event.(type) {
	case *schema.ProcessEvent:
		return uint32(ev.PID)
	case schema.ProcessEvent:
		return uint32(ev.PID)
	case *schema.FileEvent:
		return uint32(ev.ActorPID)
	case schema.FileEvent:
		return uint32(ev.ActorPID)
	case *schema.NetworkEvent:
		return uint32(ev.PID)
	case schema.NetworkEvent:
		return uint32(ev.PID)
	}
	return 0
}

func extractCommandLine(event interface{}) string {
	switch ev := event.(type) {
	case *schema.ProcessEvent:
		return ev.CommandLine
	case schema.ProcessEvent:
		return ev.CommandLine
	}
	return ""
}

func extractUser(event interface{}) string {
	switch ev := event.(type) {
	case *schema.ProcessEvent:
		return ev.User
	case schema.ProcessEvent:
		return ev.User
	case *schema.AuthEvent:
		return ev.User
	case schema.AuthEvent:
		return ev.User
	}
	return ""
}

func extractFilePath(event interface{}) string {
	switch ev := event.(type) {
	case *schema.FileEvent:
		return ev.Path
	case schema.FileEvent:
		return ev.Path
	case *schema.ProcessEvent:
		return ev.ProcessPath
	case schema.ProcessEvent:
		return ev.ProcessPath
	}
	return ""
}

func extractFileOperation(event interface{}) string {
	switch ev := event.(type) {
	case *schema.FileEvent:
		return ev.Operation
	case schema.FileEvent:
		return ev.Operation
	}
	return ""
}

func extractProcessName(event interface{}) string {
	switch ev := event.(type) {
	case *schema.ProcessEvent:
		return ev.ProcessName
	case schema.ProcessEvent:
		return ev.ProcessName
	}
	return ""
}

func extractDestIP(event interface{}) string {
	switch ev := event.(type) {
	case *schema.NetworkEvent:
		return ev.DestIP
	case schema.NetworkEvent:
		return ev.DestIP
	}
	return ""
}

func extractDestPort(event interface{}) int {
	switch ev := event.(type) {
	case *schema.NetworkEvent:
		return ev.DestPt
	case schema.NetworkEvent:
		return ev.DestPt
	}
	return 0
}

func extractDomain(event interface{}) string {
	switch ev := event.(type) {
	case *schema.NetworkEvent:
		return ev.Domain
	case schema.NetworkEvent:
		return ev.Domain
	}
	return ""
}

func extractOS(event interface{}) string {
	switch ev := event.(type) {
	case *schema.ProcessEvent:
		return ev.OS
	case schema.ProcessEvent:
		return ev.OS
	case *schema.FileEvent:
		return ev.OS
	case schema.FileEvent:
		return ev.OS
	case *schema.NetworkEvent:
		return ev.OS
	case schema.NetworkEvent:
		return ev.OS
	case *schema.AuthEvent:
		return ev.OS
	case schema.AuthEvent:
		return ev.OS
	}
	return ""
}
