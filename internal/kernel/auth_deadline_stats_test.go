package kernel

import "testing"

func Test_sortedUint32Percentile(t *testing.T) {
	samples := []uint32{1, 2, 3, 4, 100}
	if got := sortedUint32Percentile(samples, 50); got != 3 {
		t.Fatalf("p50=%d want 3", got)
	}
	if got := sortedUint32Percentile(samples, 95); got != 100 {
		t.Fatalf("p95=%d want 100", got)
	}
	if got := sortedUint32Percentile(nil, 50); got != 0 {
		t.Fatalf("empty=%d", got)
	}
}
