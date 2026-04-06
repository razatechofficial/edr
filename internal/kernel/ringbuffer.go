package kernel

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
)

var (
	// ErrBufferFull is returned when a write exceeds available ring buffer space.
	ErrBufferFull = errors.New("ring buffer full")
	// ErrBufferClosed is returned when operating on a closed ring buffer.
	ErrBufferClosed = errors.New("ring buffer closed")
	// ErrMessageTooBig is returned when a message exceeds the buffer capacity.
	ErrMessageTooBig = errors.New("message exceeds buffer capacity")
)

const (
	// DefaultBufferSize is the default ring buffer capacity (64MB).
	DefaultBufferSize = 64 * 1024 * 1024
	headerSize        = 4
)

// RingBufferStats contains operational metrics for a ring buffer.
type RingBufferStats struct {
	Produced  uint64
	Consumed  uint64
	Dropped   uint64
	BytesUsed uint64
	Capacity  uint64
}

// RingBuffer is a lock-free single-producer multi-consumer byte ring buffer
// designed for high-throughput kernel event transport. Messages are stored
// with a 4-byte little-endian length prefix followed by the payload.
type RingBuffer struct {
	buf      []byte
	mask     uint64
	capacity uint64
	writePos atomic.Uint64
	readPos  atomic.Uint64
	produced atomic.Uint64
	consumed atomic.Uint64
	dropped  atomic.Uint64
	closed   atomic.Bool
	notify   chan struct{}
	done     chan struct{}
}

func nextPowerOf2(v uint64) uint64 {
	if v == 0 {
		return 1
	}
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v |= v >> 32
	return v + 1
}

// NewRingBuffer creates a ring buffer with the given capacity in bytes.
// The capacity is rounded up to the next power of 2 for efficient modulo
// via bitwise AND. A non-positive capacity defaults to DefaultBufferSize.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = DefaultBufferSize
	}
	c := nextPowerOf2(uint64(capacity))
	return &RingBuffer{
		buf:      make([]byte, c),
		mask:     c - 1,
		capacity: c,
		notify:   make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

// writeTo copies src into the ring buffer at the given logical position,
// handling wrap-around at the buffer boundary.
func (rb *RingBuffer) writeTo(pos uint64, src []byte) {
	idx := pos & rb.mask
	n := copy(rb.buf[idx:], src)
	if n < len(src) {
		copy(rb.buf, src[n:])
	}
}

// readFrom copies len(dst) bytes from the ring buffer at the given logical
// position into dst, handling wrap-around at the buffer boundary.
func (rb *RingBuffer) readFrom(pos uint64, dst []byte) {
	idx := pos & rb.mask
	n := copy(dst, rb.buf[idx:])
	if n < len(dst) {
		copy(dst[n:], rb.buf)
	}
}

// Write appends a message to the ring buffer. Returns ErrBufferFull if there
// is insufficient space. This method is safe for a single producer goroutine.
func (rb *RingBuffer) Write(data []byte) error {
	if rb.closed.Load() {
		return ErrBufferClosed
	}

	total := uint64(headerSize) + uint64(len(data))
	if total > rb.capacity {
		return ErrMessageTooBig
	}

	wp := rb.writePos.Load()
	rp := rb.readPos.Load()

	if rb.capacity-(wp-rp) < total {
		rb.dropped.Add(1)
		return ErrBufferFull
	}

	var hdr [headerSize]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(data)))
	rb.writeTo(wp, hdr[:])
	if len(data) > 0 {
		rb.writeTo(wp+headerSize, data)
	}

	rb.writePos.Store(wp + total)
	rb.produced.Add(1)

	// Non-blocking signal to wake any blocked reader.
	select {
	case rb.notify <- struct{}{}:
	default:
	}

	return nil
}

// tryRead performs a non-blocking CAS read. It returns the message data and
// true on success, or nil and false when no data is available. On CAS
// contention with another consumer it retries internally.
func (rb *RingBuffer) tryRead() ([]byte, bool) {
	for {
		rp := rb.readPos.Load()
		wp := rb.writePos.Load()

		if rp == wp {
			return nil, false
		}

		// Read the length header (stack-allocated, zero alloc).
		var hdr [headerSize]byte
		rb.readFrom(rp, hdr[:])
		msgLen := uint64(binary.LittleEndian.Uint32(hdr[:]))

		// Copy payload before advancing readPos so the writer cannot
		// reclaim this region until the CAS below succeeds.
		data := make([]byte, msgLen)
		if msgLen > 0 {
			rb.readFrom(rp+headerSize, data)
		}

		advance := uint64(headerSize) + msgLen
		if rb.readPos.CompareAndSwap(rp, rp+advance) {
			rb.consumed.Add(1)
			return data, true
		}
		// Another consumer won the CAS; discard the copy and retry.
	}
}

// Read returns the next available message from the ring buffer. The returned
// byte slice is a copy safe for concurrent use. Read blocks until data is
// available. Returns ErrBufferClosed if the buffer has been closed and no
// messages remain.
func (rb *RingBuffer) Read() ([]byte, error) {
	for {
		if data, ok := rb.tryRead(); ok {
			return data, nil
		}
		if rb.closed.Load() {
			return nil, ErrBufferClosed
		}
		select {
		case <-rb.notify:
		case <-rb.done:
		}
	}
}

// TryRead attempts a non-blocking read. Returns nil, nil if no data is
// available. Returns ErrBufferClosed if the buffer is closed and empty.
func (rb *RingBuffer) TryRead() ([]byte, error) {
	if data, ok := rb.tryRead(); ok {
		return data, nil
	}
	if rb.closed.Load() {
		return nil, ErrBufferClosed
	}
	return nil, nil
}

// Stats returns current buffer metrics.
func (rb *RingBuffer) Stats() RingBufferStats {
	wp := rb.writePos.Load()
	rp := rb.readPos.Load()
	return RingBufferStats{
		Produced:  rb.produced.Load(),
		Consumed:  rb.consumed.Load(),
		Dropped:   rb.dropped.Load(),
		BytesUsed: wp - rp,
		Capacity:  rb.capacity,
	}
}

// Close marks the buffer as closed. Subsequent writes return ErrBufferClosed.
// Pending reads can still drain remaining data before receiving ErrBufferClosed.
func (rb *RingBuffer) Close() {
	if rb.closed.CompareAndSwap(false, true) {
		close(rb.done)
	}
}

// Reset clears all data and resets positions and metrics. Not safe during
// concurrent use; the caller must ensure exclusive access.
func (rb *RingBuffer) Reset() {
	rb.writePos.Store(0)
	rb.readPos.Store(0)
	rb.produced.Store(0)
	rb.consumed.Store(0)
	rb.dropped.Store(0)
	rb.closed.Store(false)
	clear(rb.buf)
	rb.notify = make(chan struct{}, 1)
	rb.done = make(chan struct{})
}
