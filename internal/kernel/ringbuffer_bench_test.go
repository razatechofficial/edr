package kernel

import (
	"sync"
	"testing"
)

func BenchmarkRingBufferWrite(b *testing.B) {
	rb := NewRingBuffer(DefaultBufferSize)
	data := make([]byte, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rb.Write(data)
		rb.TryRead()
	}
}

func BenchmarkRingBufferReadWrite(b *testing.B) {
	rb := NewRingBuffer(DefaultBufferSize)
	data := make([]byte, 256)

	const readers = 4
	var wg sync.WaitGroup
	done := make(chan struct{})

	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					for {
						if d, _ := rb.TryRead(); d == nil {
							return
						}
					}
				default:
					rb.TryRead()
				}
			}
		}()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for rb.Write(data) != nil {
			rb.TryRead()
		}
	}
	b.StopTimer()

	close(done)
	wg.Wait()
}

func BenchmarkRingBufferZeroAlloc(b *testing.B) {
	rb := NewRingBuffer(DefaultBufferSize)
	data := make([]byte, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rb.Write(data)
		rb.TryRead()
	}
}
