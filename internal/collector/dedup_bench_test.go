package collector

import (
	"fmt"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// BenchmarkFileDeduper measures the steady-state cost of one
// ShouldEmitFile call. After P1-19 the dedupe key uses FNV-64a instead
// of SHA-256; this benchmark guards against regression.
func BenchmarkFileDeduper(b *testing.B) {
	d := NewFileDeduper(500 * time.Millisecond)
	paths := make([]string, 128)
	for i := range paths {
		paths[i] = fmt.Sprintf("/var/log/app/%d.log", i)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.ShouldEmitFile(schema.EventFile, 1000+i%128, paths[i%len(paths)], "write")
	}
}

// BenchmarkFileDeduperHotKey hammers a single key so the cache always
// hits and we see the hash + map-lookup cost in isolation.
func BenchmarkFileDeduperHotKey(b *testing.B) {
	d := NewFileDeduper(500 * time.Millisecond)
	const path = "/etc/passwd"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d.ShouldEmitFile(schema.EventFile, 1, path, "write")
	}
}
