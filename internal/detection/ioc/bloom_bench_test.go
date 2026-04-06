package ioc

import (
	"fmt"
	"testing"
)

func BenchmarkBloomFilterAdd(b *testing.B) {
	bf := NewBloomFilter(1_000_000, 0.001)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Add(fmt.Sprintf("item-%d", i))
	}
}

func BenchmarkBloomFilterContains(b *testing.B) {
	bf := NewBloomFilter(100_000, 0.001)
	for i := range 100_000 {
		bf.Add(fmt.Sprintf("item-%d", i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Contains(fmt.Sprintf("item-%d", i%100_000))
	}
}

func BenchmarkBloomFilterContainsMiss(b *testing.B) {
	bf := NewBloomFilter(100_000, 0.001)
	for i := range 100_000 {
		bf.Add(fmt.Sprintf("item-%d", i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Contains(fmt.Sprintf("miss-%d", i))
	}
}
