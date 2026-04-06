package collectors

import (
	"math"
	"math/rand"
	"testing"

	"go.uber.org/zap"
)

func TestShannonEntropy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    []byte
		wantMin float64
		wantMax float64
	}{
		{
			name:    "empty",
			data:    nil,
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "all zeros",
			data:    make([]byte, 256),
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "repeated A",
			data:    []byte("AAAAAAAAAAAAAAAA"),
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "random bytes",
			data:    randomBytes(10000),
			wantMin: 7.5,
			wantMax: 8.0,
		},
		{
			name:    "english text",
			data:    []byte("The quick brown fox jumps over the lazy dog. This is a reasonably long English sentence that should exhibit typical character frequency distribution patterns found in natural language text."),
			wantMin: 3.5,
			wantMax: 5.5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := shannonEntropy(tc.data)

			if tc.wantMin == tc.wantMax {
				if math.Abs(got-tc.wantMin) > 0.001 {
					t.Errorf("shannonEntropy = %f, want %f", got, tc.wantMin)
				}
				return
			}

			if got < tc.wantMin || got > tc.wantMax {
				t.Errorf("shannonEntropy = %f, want [%f, %f]", got, tc.wantMin, tc.wantMax)
			}
		})
	}
}

func TestFileCollectorName(t *testing.T) {
	t.Parallel()
	c := NewFileCollector(zap.NewNop())
	if got := c.Name(); got != "file" {
		t.Errorf("Name() = %q, want %q", got, "file")
	}
}

func randomBytes(n int) []byte {
	r := rand.New(rand.NewSource(42))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
	return b
}
