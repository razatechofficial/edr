package kernel

import "testing"

// BenchmarkEnvelopeAllocFresh measures allocating a new envelope map
// per event (the pre-P2-9 baseline).
func BenchmarkEnvelopeAllocFresh(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := make(map[string]interface{}, 16)
		m["k1"] = i
		m["k2"] = "value"
		_ = m
	}
}

// BenchmarkEnvelopePool measures the same workload through the
// envelope sync.Pool. The win is in allocations / op, not raw ns / op.
func BenchmarkEnvelopePool(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m := getEnvelope()
		m["k1"] = i
		m["k2"] = "value"
		putEnvelope(m)
	}
}
