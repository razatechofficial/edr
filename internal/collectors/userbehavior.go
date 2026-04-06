package collectors

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

const (
	defaultActivityWindow    = 24 * time.Hour
	anomalyCheckInterval     = 5 * time.Minute
	minActivitiesForBaseline = 50
)

// UserAnomalyEvent is emitted when a user's behavior deviates
// significantly from their established baseline.
type UserAnomalyEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	User        string    `json:"user"`
	AnomalyType string    `json:"anomaly_type"`
	Description string    `json:"description"`
	Score       float64   `json:"score"`
}

type activityEntry struct {
	timestamp time.Time
	kind      string
	detail    string
}

type userProfile struct {
	activities  []activityEntry
	hourCounts  [24]int
	commands    map[string]int
	networkDsts map[string]int
}

// ActivityTracker maintains per-user activity baselines within a sliding
// time window and computes anomaly scores from deviations.
type ActivityTracker struct {
	mu     sync.Mutex
	window time.Duration
	users  map[uint32]*userProfile
}

// UserBehaviorCollector tracks per-user activity patterns—login times,
// command patterns, network destinations—and emits anomaly events when
// behavior deviates from the established baseline.
type UserBehaviorCollector struct {
	logger  *zap.Logger
	out     chan<- interface{}
	tracker *ActivityTracker
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewUserBehaviorCollector creates a UserBehaviorCollector with the given logger.
func NewUserBehaviorCollector(logger *zap.Logger) *UserBehaviorCollector {
	return &UserBehaviorCollector{
		logger: logger,
		tracker: &ActivityTracker{
			window: defaultActivityWindow,
			users:  make(map[uint32]*userProfile),
		},
	}
}

// Name returns the collector identifier.
func (c *UserBehaviorCollector) Name() string { return "userbehavior" }

// EventTypes returns the coarse event types observed for baselining.
func (c *UserBehaviorCollector) EventTypes() []events.EventType {
	return []events.EventType{events.EventProcess, events.EventNetwork, events.EventAuth}
}

// Start stores the output channel and launches the anomaly detection loop.
func (c *UserBehaviorCollector) Start(ctx context.Context, _ *kernel.RingBuffer, out chan<- interface{}) error {
	c.out = out
	ctx, c.cancel = context.WithCancel(ctx)
	c.wg.Add(1)
	go c.anomalyLoop(ctx)
	return nil
}

// Stop cancels the anomaly loop and waits for it to exit.
func (c *UserBehaviorCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	return nil
}

func (c *UserBehaviorCollector) processRaw(evt *RawEvent) {
	switch evt.Type {
	case EventProcessExec:
		r := newPayloadReader(evt.Payload)
		_ = r.Uint32() // ppid
		exePath := r.String()
		if r.Err() == nil {
			c.tracker.record(evt.UID, evt.Timestamp, "exec", exePath)
		}
	case EventNetworkConnect:
		r := newPayloadReader(evt.Payload)
		family := r.Uint8()
		_ = r.Uint8()            // proto
		_ = r.Uint8()            // direction
		_ = readAddr(r, family)  // src
		_ = r.Uint16()           // srcPort
		dst := readAddr(r, family)
		if r.Err() == nil {
			c.tracker.record(evt.UID, evt.Timestamp, "network", dst)
		}
	case EventAuthentication:
		r := newPayloadReader(evt.Payload)
		_ = r.Uint8() // auth type
		_ = r.Uint8() // outcome
		userName := r.String()
		if r.Err() == nil {
			c.tracker.record(evt.UID, evt.Timestamp, "auth", userName)
		}
	}
}

func (t *ActivityTracker) record(uid uint32, ts time.Time, kind, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	p := t.users[uid]
	if p == nil {
		p = &userProfile{
			commands:    make(map[string]int),
			networkDsts: make(map[string]int),
		}
		t.users[uid] = p
	}

	p.activities = append(p.activities, activityEntry{
		timestamp: ts,
		kind:      kind,
		detail:    detail,
	})
	p.hourCounts[ts.Hour()]++

	switch kind {
	case "exec":
		p.commands[detail]++
	case "network":
		p.networkDsts[detail]++
	}
}

func (t *ActivityTracker) evict() {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-t.window)
	for uid, p := range t.users {
		n := 0
		for _, a := range p.activities {
			if a.timestamp.After(cutoff) {
				p.activities[n] = a
				n++
			}
		}
		p.activities = p.activities[:n]
		if n == 0 {
			delete(t.users, uid)
		}
	}
}

func (t *ActivityTracker) detectAnomalies() []UserAnomalyEvent {
	t.mu.Lock()
	defer t.mu.Unlock()

	var anomalies []UserAnomalyEvent
	now := time.Now().UTC()
	currentHour := now.Hour()

	for uid, p := range t.users {
		if len(p.activities) < minActivitiesForBaseline {
			continue
		}

		var totalHourly float64
		for _, c := range p.hourCounts {
			totalHourly += float64(c)
		}
		avgHourly := totalHourly / 24
		currentHourCount := float64(p.hourCounts[currentHour])

		if avgHourly > 0 && currentHourCount > 0 {
			deviation := math.Abs(currentHourCount-avgHourly) / avgHourly
			if deviation > 2.0 {
				anomalies = append(anomalies, UserAnomalyEvent{
					Timestamp:   now,
					User:        resolveUser(uid),
					AnomalyType: "unusual_hours",
					Description: "activity at unusual time of day",
					Score:       math.Min(deviation/3.0, 1.0),
				})
			}
		}
	}
	return anomalies
}

func (c *UserBehaviorCollector) anomalyLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(anomalyCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.tracker.evict()
			for _, a := range c.tracker.detectAnomalies() {
				c.emit(&a)
			}
		}
	}
}

func (c *UserBehaviorCollector) emit(evt interface{}) {
	select {
	case c.out <- evt:
	default:
		c.logger.Warn("output channel full, dropping user behavior event")
	}
}
