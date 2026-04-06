package collectors

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/razatechofficial/edr/internal/kernel"
	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// EventSubType is the wire-format event discriminator written by kernel drivers.
type EventSubType uint16

const (
	EventProcessExec    EventSubType = iota + 1
	EventProcessExit
	EventProcessFork
	EventThreadCreate
	EventThreadExit
	EventFileOpen
	EventFileWrite
	EventFileDelete
	EventFileRename
	EventFileCreate
	EventNetworkConnect
	EventNetworkAccept
	EventNetworkBind
	EventNetworkDNS
	EventRegistryCreate
	EventRegistrySet
	EventRegistryDelete
	EventMemoryAlloc
	EventMemoryWrite
	EventMemoryProtect
	EventAuthentication
)

const rawEventHeaderSize = 26

var errShortEvent = errors.New("event data shorter than header")

// RawEvent is a decoded kernel event header with its typed payload.
type RawEvent struct {
	Type      EventSubType
	Timestamp time.Time
	PID       uint32
	TID       uint32
	UID       uint32
	GID       uint32
	Payload   []byte
}

func decodeRawEvent(data []byte) (*RawEvent, error) {
	if len(data) < rawEventHeaderSize {
		return nil, errShortEvent
	}
	evt := &RawEvent{
		Type:      EventSubType(binary.LittleEndian.Uint16(data[0:2])),
		Timestamp: time.Unix(0, int64(binary.LittleEndian.Uint64(data[2:10]))),
		PID:       binary.LittleEndian.Uint32(data[10:14]),
		TID:       binary.LittleEndian.Uint32(data[14:18]),
		UID:       binary.LittleEndian.Uint32(data[18:22]),
		GID:       binary.LittleEndian.Uint32(data[22:26]),
	}
	if len(data) > rawEventHeaderSize {
		evt.Payload = data[rawEventHeaderSize:]
	}
	return evt, nil
}

var subTypeCategory = map[EventSubType]events.EventType{
	EventProcessExec:    events.EventProcess,
	EventProcessExit:    events.EventProcess,
	EventProcessFork:    events.EventProcess,
	EventThreadCreate:   events.EventProcess,
	EventThreadExit:     events.EventProcess,
	EventFileOpen:       events.EventFile,
	EventFileWrite:      events.EventFile,
	EventFileDelete:     events.EventFile,
	EventFileRename:     events.EventFile,
	EventFileCreate:     events.EventFile,
	EventNetworkConnect: events.EventNetwork,
	EventNetworkAccept:  events.EventNetwork,
	EventNetworkBind:    events.EventNetwork,
	EventNetworkDNS:     events.EventDNS,
	EventRegistryCreate: events.EventRegistry,
	EventRegistrySet:    events.EventRegistry,
	EventRegistryDelete: events.EventRegistry,
	EventMemoryAlloc:    events.EventMemory,
	EventMemoryWrite:    events.EventMemory,
	EventMemoryProtect:  events.EventMemory,
	EventAuthentication: events.EventAuth,
}

// Collector processes kernel events from the ring buffer and emits normalized events.
type Collector interface {
	Name() string
	Start(ctx context.Context, rb *kernel.RingBuffer, out chan<- interface{}) error
	Stop() error
	EventTypes() []events.EventType
}

// rawProcessor is implemented by collectors that accept pre-decoded kernel events
// dispatched by the Manager.
type rawProcessor interface {
	processRaw(evt *RawEvent)
}

// Manager coordinates all collectors, reading from the kernel ring buffer
// and dispatching events to the appropriate collector.
type Manager struct {
	logger     *zap.Logger
	collectors []Collector
	dispatch   map[events.EventType][]rawProcessor
	out        chan interface{}
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewManager creates a Manager that coordinates the given collectors.
func NewManager(logger *zap.Logger, collectors ...Collector) *Manager {
	m := &Manager{
		logger:     logger,
		collectors: collectors,
		dispatch:   make(map[events.EventType][]rawProcessor),
		out:        make(chan interface{}, 4096),
	}
	for _, c := range collectors {
		if rp, ok := c.(rawProcessor); ok {
			for _, et := range c.EventTypes() {
				m.dispatch[et] = append(m.dispatch[et], rp)
			}
		}
	}
	return m
}

// Start begins reading from the ring buffer and dispatching events to collectors.
// The returned channel receives enriched events from all active collectors.
func (m *Manager) Start(ctx context.Context, rb *kernel.RingBuffer) (<-chan interface{}, error) {
	ctx, m.cancel = context.WithCancel(ctx)

	started := make([]Collector, 0, len(m.collectors))
	for _, c := range m.collectors {
		if err := c.Start(ctx, rb, m.out); err != nil {
			for _, s := range started {
				_ = s.Stop()
			}
			m.cancel()
			return nil, fmt.Errorf("starting collector %s: %w", c.Name(), err)
		}
		started = append(started, c)
		m.logger.Info("started collector", zap.String("name", c.Name()))
	}

	m.wg.Add(1)
	go m.readLoop(ctx, rb)

	return m.out, nil
}

func (m *Manager) readLoop(ctx context.Context, rb *kernel.RingBuffer) {
	defer m.wg.Done()

	backoff := time.Microsecond
	const maxBackoff = time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, err := rb.TryRead()
		if err != nil {
			if err == kernel.ErrBufferClosed {
				return
			}
			m.logger.Error("ring buffer read failed", zap.Error(err))
			time.Sleep(time.Millisecond)
			continue
		}
		if data == nil {
			time.Sleep(backoff)
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}
		backoff = time.Microsecond

		evt, err := decodeRawEvent(data)
		if err != nil {
			m.logger.Warn("malformed kernel event", zap.Error(err))
			continue
		}

		cat, ok := subTypeCategory[evt.Type]
		if !ok {
			m.logger.Warn("unknown event sub-type", zap.Uint16("type", uint16(evt.Type)))
			continue
		}
		for _, rp := range m.dispatch[cat] {
			rp.processRaw(evt)
		}
	}
}

// Stop gracefully shuts down the read loop and all collectors.
func (m *Manager) Stop() error {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()

	var firstErr error
	for _, c := range m.collectors {
		if err := c.Stop(); err != nil {
			m.logger.Error("collector stop failed",
				zap.String("name", c.Name()),
				zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	close(m.out)
	return firstErr
}

// payloadReader provides sequential little-endian decoding of a binary payload.
// Once an error occurs, all subsequent reads return zero values.
type payloadReader struct {
	data []byte
	off  int
	err  error
}

func newPayloadReader(data []byte) *payloadReader {
	return &payloadReader{data: data}
}

func (r *payloadReader) remaining() int {
	return len(r.data) - r.off
}

// Uint8 reads a single byte.
func (r *payloadReader) Uint8() uint8 {
	if r.err != nil || r.remaining() < 1 {
		r.err = errShortEvent
		return 0
	}
	v := r.data[r.off]
	r.off++
	return v
}

// Uint16 reads a little-endian uint16.
func (r *payloadReader) Uint16() uint16 {
	if r.err != nil || r.remaining() < 2 {
		r.err = errShortEvent
		return 0
	}
	v := binary.LittleEndian.Uint16(r.data[r.off:])
	r.off += 2
	return v
}

// Uint32 reads a little-endian uint32.
func (r *payloadReader) Uint32() uint32 {
	if r.err != nil || r.remaining() < 4 {
		r.err = errShortEvent
		return 0
	}
	v := binary.LittleEndian.Uint32(r.data[r.off:])
	r.off += 4
	return v
}

// Int32 reads a little-endian int32.
func (r *payloadReader) Int32() int32 {
	return int32(r.Uint32())
}

// Uint64 reads a little-endian uint64.
func (r *payloadReader) Uint64() uint64 {
	if r.err != nil || r.remaining() < 8 {
		r.err = errShortEvent
		return 0
	}
	v := binary.LittleEndian.Uint64(r.data[r.off:])
	r.off += 8
	return v
}

// String reads a uint16 length-prefixed UTF-8 string.
func (r *payloadReader) String() string {
	n := int(r.Uint16())
	if r.err != nil || r.remaining() < n {
		r.err = errShortEvent
		return ""
	}
	s := string(r.data[r.off : r.off+n])
	r.off += n
	return s
}

// Bytes reads exactly n bytes into a new slice.
func (r *payloadReader) Bytes(n int) []byte {
	if r.err != nil || r.remaining() < n {
		r.err = errShortEvent
		return nil
	}
	b := make([]byte, n)
	copy(b, r.data[r.off:r.off+n])
	r.off += n
	return b
}

// Err returns the first decoding error encountered, if any.
func (r *payloadReader) Err() error {
	return r.err
}

// maxHashFileSize is the upper bound for file hashing. Binaries larger
// than this are skipped to avoid unbounded I/O in the event path.
const maxHashFileSize = 100 << 20 // 100 MiB
