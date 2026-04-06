package ioc

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
)

func TestBloomFilterAddContains(t *testing.T) {
	t.Parallel()
	bf := NewBloomFilter(1000, 0.01)
	items := []string{"alpha", "bravo", "charlie", "delta"}
	for _, item := range items {
		bf.Add(item)
	}
	for _, item := range items {
		if !bf.Contains(item) {
			t.Errorf("Contains(%q) = false, want true", item)
		}
	}
}

func TestBloomFilterNotContains(t *testing.T) {
	t.Parallel()
	bf := NewBloomFilter(1000, 0.01)
	bf.Add("present")
	absent := []string{"missing", "nope", "zilch", ""}
	for _, item := range absent {
		if bf.Contains(item) {
			t.Logf("Contains(%q) = true (false positive), acceptable", item)
		}
	}
}

func TestBloomFilterZeroFalseNegatives(t *testing.T) {
	t.Parallel()
	const n = 10_000
	bf := NewBloomFilter(n, 0.01)
	for i := 0; i < n; i++ {
		bf.Add(fmt.Sprintf("item-%d", i))
	}
	for i := 0; i < n; i++ {
		if !bf.Contains(fmt.Sprintf("item-%d", i)) {
			t.Fatalf("false negative at item-%d", i)
		}
	}
}

func TestBloomFilterFalsePositiveRate(t *testing.T) {
	t.Parallel()
	const n = 10_000
	bf := NewBloomFilter(n, 0.01)
	for i := 0; i < n; i++ {
		bf.Add(fmt.Sprintf("member-%d", i))
	}

	rng := rand.New(rand.NewSource(42))
	fp := 0
	const tests = 10_000
	for i := 0; i < tests; i++ {
		key := fmt.Sprintf("nonmember-%d-%d", rng.Int63(), i)
		if bf.Contains(key) {
			fp++
		}
	}
	rate := float64(fp) / float64(tests)
	if rate >= 0.01 {
		t.Errorf("false positive rate = %.4f, want < 0.01", rate)
	}
}

func TestBloomFilterCount(t *testing.T) {
	t.Parallel()
	bf := NewBloomFilter(100, 0.01)
	for i := 0; i < 42; i++ {
		bf.Add(fmt.Sprintf("x-%d", i))
	}
	if got := bf.Count(); got != 42 {
		t.Errorf("Count() = %d, want 42", got)
	}
}

func TestBloomFilterReset(t *testing.T) {
	t.Parallel()
	bf := NewBloomFilter(100, 0.01)
	bf.Add("one")
	bf.Add("two")
	bf.Reset()
	if bf.Count() != 0 {
		t.Errorf("Count() after Reset = %d, want 0", bf.Count())
	}
	if bf.Contains("one") {
		t.Error("Contains(one) after Reset = true, want false")
	}
}

func TestBloomFilterConcurrentSafe(t *testing.T) {
	t.Parallel()
	bf := NewBloomFilter(10_000, 0.01)
	var wg sync.WaitGroup
	const goroutines = 16
	const perGoroutine = 500

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				bf.Add(fmt.Sprintf("g%d-i%d", id, i))
			}
		}(g)
	}

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				bf.Contains(fmt.Sprintf("g%d-i%d", id, i))
			}
		}(g)
	}
	wg.Wait()

	if got := bf.Count(); got != goroutines*perGoroutine {
		t.Errorf("Count() = %d, want %d", got, goroutines*perGoroutine)
	}
}
