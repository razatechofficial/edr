package kernel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRingBufferWriteRead(t *testing.T) {
	t.Parallel()
	rb := NewRingBuffer(1024)

	msg := []byte("hello ring buffer")
	if err := rb.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := rb.TryRead()
	if err != nil {
		t.Fatalf("TryRead: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("Read = %q, want %q", got, msg)
	}
}

func TestRingBufferMultipleMessages(t *testing.T) {
	t.Parallel()
	rb := NewRingBuffer(1 << 16)

	const n = 100
	for i := range n {
		msg := []byte(fmt.Sprintf("msg-%04d", i))
		if err := rb.Write(msg); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	for i := range n {
		got, err := rb.TryRead()
		if err != nil {
			t.Fatalf("TryRead %d: %v", i, err)
		}
		want := fmt.Sprintf("msg-%04d", i)
		if string(got) != want {
			t.Errorf("message %d = %q, want %q", i, got, want)
		}
	}
}

func TestRingBufferWrapAround(t *testing.T) {
	t.Parallel()
	rb := NewRingBuffer(256)

	msg := make([]byte, 50)
	for i := range 4 {
		msg[0] = byte(i)
		if err := rb.Write(msg); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	for i := range 4 {
		data, err := rb.TryRead()
		if err != nil {
			t.Fatalf("TryRead %d: %v", i, err)
		}
		if data == nil {
			t.Fatalf("TryRead %d: got nil", i)
		}
		if data[0] != byte(i) {
			t.Errorf("message %d first byte = %d, want %d", i, data[0], i)
		}
	}

	for i := 4; i < 8; i++ {
		msg[0] = byte(i)
		if err := rb.Write(msg); err != nil {
			t.Fatalf("Write %d (wrap): %v", i, err)
		}
	}

	for i := 4; i < 8; i++ {
		data, err := rb.TryRead()
		if err != nil {
			t.Fatalf("TryRead %d (wrap): %v", i, err)
		}
		if data == nil {
			t.Fatalf("TryRead %d (wrap): got nil", i)
		}
		if data[0] != byte(i) {
			t.Errorf("message %d (wrap) first byte = %d, want %d", i, data[0], i)
		}
	}
}

func TestRingBufferFull(t *testing.T) {
	t.Parallel()
	rb := NewRingBuffer(128)

	payload := make([]byte, 4) // 4 payload + 4 header = 8 bytes per message
	capacity := 128 / 8        // exactly 16 messages fill the buffer

	for i := range capacity {
		if err := rb.Write(payload); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	err := rb.Write(payload)
	if err != ErrBufferFull {
		t.Errorf("Write to full buffer: got %v, want ErrBufferFull", err)
	}
}

func TestRingBufferClosed(t *testing.T) {
	t.Parallel()
	rb := NewRingBuffer(128)
	rb.Close()

	err := rb.Write([]byte("hello"))
	if err != ErrBufferClosed {
		t.Errorf("Write after close: got %v, want ErrBufferClosed", err)
	}
}

func TestRingBufferMessageTooBig(t *testing.T) {
	t.Parallel()
	rb := NewRingBuffer(64)

	msg := make([]byte, 100)
	err := rb.Write(msg)
	if err != ErrMessageTooBig {
		t.Errorf("Write oversized message: got %v, want ErrMessageTooBig", err)
	}
}

func TestRingBufferConcurrentReadWrite(t *testing.T) {
	t.Parallel()
	rb := NewRingBuffer(1 << 20)
	const numMessages = 10000
	const numReaders = 4

	var (
		received sync.Map
		wg       sync.WaitGroup
		written  atomic.Int64
	)

	for range numReaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				data, err := rb.Read()
				if err == ErrBufferClosed {
					return
				}
				if err != nil {
					t.Errorf("Read: %v", err)
					return
				}
				if len(data) != 4 {
					t.Errorf("message length = %d, want 4", len(data))
					return
				}
				idx := binary.LittleEndian.Uint32(data)
				if _, loaded := received.LoadOrStore(idx, true); loaded {
					t.Errorf("message %d consumed more than once", idx)
				}
			}
		}()
	}

	for i := range numMessages {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], uint32(i))
		if err := rb.Write(buf[:]); err == nil {
			written.Add(1)
		}
	}

	rb.Close()
	wg.Wait()

	count := int64(0)
	received.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != written.Load() {
		t.Errorf("received %d messages, want %d (written)", count, written.Load())
	}
}

func TestRingBufferStats(t *testing.T) {
	t.Parallel()
	rb := NewRingBuffer(1024)

	s := rb.Stats()
	if s.Capacity != 1024 {
		t.Errorf("Capacity = %d, want 1024", s.Capacity)
	}
	if s.Produced != 0 || s.Consumed != 0 || s.Dropped != 0 {
		t.Errorf("fresh stats not zero: %+v", s)
	}

	for range 5 {
		_ = rb.Write([]byte("test"))
	}
	s = rb.Stats()
	if s.Produced != 5 {
		t.Errorf("Produced = %d, want 5", s.Produced)
	}
	if s.BytesUsed != 5*(headerSize+4) {
		t.Errorf("BytesUsed = %d, want %d", s.BytesUsed, 5*(headerSize+4))
	}

	for range 3 {
		_, _ = rb.TryRead()
	}
	s = rb.Stats()
	if s.Consumed != 3 {
		t.Errorf("Consumed = %d, want 3", s.Consumed)
	}
}

func TestRingBufferReset(t *testing.T) {
	t.Parallel()
	rb := NewRingBuffer(1024)

	for range 10 {
		_ = rb.Write([]byte("data"))
	}

	rb.Reset()

	s := rb.Stats()
	if s.Produced != 0 || s.Consumed != 0 || s.BytesUsed != 0 {
		t.Errorf("stats after reset not zero: %+v", s)
	}

	data, err := rb.TryRead()
	if err != nil {
		t.Fatalf("TryRead after reset: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil data after reset, got %q", data)
	}
}

func TestRingBufferTryReadEmpty(t *testing.T) {
	t.Parallel()
	rb := NewRingBuffer(256)

	data, err := rb.TryRead()
	if err != nil {
		t.Fatalf("TryRead on empty: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil data on empty buffer, got %q", data)
	}
}
