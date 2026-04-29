package collector

import (
	"sync"
	"testing"
	"time"
)

func TestBoundedLRU_PutGet(t *testing.T) {
	lru := NewBoundedLRU[string, int](4, 0)
	lru.Put("a", 1)
	lru.Put("b", 2)
	if v, ok := lru.Get("a"); !ok || v != 1 {
		t.Fatalf("expected a=1, got %v ok=%v", v, ok)
	}
	if v, ok := lru.Get("b"); !ok || v != 2 {
		t.Fatalf("expected b=2, got %v ok=%v", v, ok)
	}
	if _, ok := lru.Get("missing"); ok {
		t.Fatal("expected miss")
	}
}

func TestBoundedLRU_EvictsOldestWhenFull(t *testing.T) {
	lru := NewBoundedLRU[int, int](2, 0)
	lru.Put(1, 100)
	lru.Put(2, 200)
	if _, ok := lru.Get(1); !ok {
		t.Fatal("expected 1 present")
	}
	lru.Put(3, 300) // 2 is now LRU and should be evicted
	if _, ok := lru.Get(2); ok {
		t.Fatal("expected 2 evicted")
	}
	if _, ok := lru.Get(1); !ok {
		t.Fatal("expected 1 retained")
	}
	if _, ok := lru.Get(3); !ok {
		t.Fatal("expected 3 present")
	}
	size, evicts, _ := lru.Stats()
	if size != 2 || evicts != 1 {
		t.Fatalf("size=%d evicts=%d", size, evicts)
	}
}

func TestBoundedLRU_TTLExpires(t *testing.T) {
	lru := NewBoundedLRU[string, string](16, 50*time.Millisecond)
	now := time.Now()
	lru.now = func() time.Time { return now }
	lru.Put("k", "v")
	if _, ok := lru.Get("k"); !ok {
		t.Fatal("expected hit before TTL")
	}
	now = now.Add(100 * time.Millisecond)
	if _, ok := lru.Get("k"); ok {
		t.Fatal("expected miss after TTL")
	}
	_, _, exps := lru.Stats()
	if exps != 1 {
		t.Fatalf("expirations=%d, want 1", exps)
	}
}

func TestBoundedLRU_SweepReapsExpired(t *testing.T) {
	lru := NewBoundedLRU[int, int](16, 10*time.Millisecond)
	now := time.Now()
	lru.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		lru.Put(i, i)
	}
	now = now.Add(50 * time.Millisecond)
	if n := lru.Sweep(); n != 5 {
		t.Fatalf("sweep reaped %d, want 5", n)
	}
	if lru.Len() != 0 {
		t.Fatalf("len=%d, want 0", lru.Len())
	}
}

func TestBoundedLRU_DeletePurge(t *testing.T) {
	lru := NewBoundedLRU[int, int](8, 0)
	lru.Put(1, 1)
	lru.Put(2, 2)
	if !lru.Delete(1) {
		t.Fatal("delete should succeed")
	}
	if lru.Delete(1) {
		t.Fatal("double delete should fail")
	}
	lru.Purge()
	if lru.Len() != 0 {
		t.Fatalf("len=%d after purge", lru.Len())
	}
}

func TestBoundedLRU_ConcurrentAccess(t *testing.T) {
	lru := NewBoundedLRU[int, int](256, 0)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				lru.Put(id*1000+i, i)
				lru.Get(id*1000 + i)
			}
		}(w)
	}
	wg.Wait()
	if lru.Len() > 256 {
		t.Fatalf("len=%d exceeds cap", lru.Len())
	}
}
