package benchmark

import (
	"testing"

	"github.com/razatechofficial/edr/internal/detection/ioc"
	"go.uber.org/zap"
)

func BenchmarkIOCLookup(b *testing.B) {
	m := ioc.NewMatcher(zap.NewNop())
	m.Hashes().Add(ioc.HashEntry{Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Type: ioc.HashSHA256})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.CheckHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	}
}
