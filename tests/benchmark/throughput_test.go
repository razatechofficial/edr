//go:build benchmark

package benchmark

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/razatechofficial/edr/internal/kernel"
)

func BenchmarkEventThroughput(b *testing.B) {
	rb := kernel.NewRingBuffer(kernel.DefaultBufferSize)
	data := make([]byte, 256)

	var consumed atomic.Int64
	var wg sync.WaitGroup

	const consumers = 4
	done := make(chan struct{})

	for range consumers {
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
						consumed.Add(1)
					}
				default:
					if d, _ := rb.TryRead(); d != nil {
						consumed.Add(1)
					}
				}
			}
		}()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for rb.Write(data) != nil {
			// back-pressure: drain one before retrying
			if d, _ := rb.TryRead(); d != nil {
				consumed.Add(1)
			}
		}
	}
	b.StopTimer()

	close(done)
	wg.Wait()

	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/sec")
}
