package ioc

import (
	"hash"
	"hash/fnv"
	"math"
	"sync"
)

// BloomFilter is a space-efficient probabilistic data structure for set membership testing.
// It guarantees zero false negatives: if Contains returns false, the element is definitely
// not in the set. False positives are possible at a controlled rate.
type BloomFilter struct {
	bits    []uint64
	size    uint64
	numHash uint32
	count   uint64
	mu      sync.RWMutex
}

// NewBloomFilter creates a Bloom filter sized for expectedItems at the given
// false-positive rate. Optimal bit-array size and hash count are computed as:
//
//	m = -(n * ln(p)) / (ln(2)^2)
//	k = (m / n) * ln(2)
func NewBloomFilter(expectedItems int, fpRate float64) *BloomFilter {
	if expectedItems <= 0 {
		expectedItems = 1
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.01
	}

	n := float64(expectedItems)
	ln2 := math.Ln2
	m := math.Ceil(-(n * math.Log(fpRate)) / (ln2 * ln2))
	k := math.Ceil((m / n) * ln2)

	words := (uint64(m) + 63) / 64

	return &BloomFilter{
		bits:    make([]uint64, words),
		size:    uint64(m),
		numHash: uint32(k),
	}
}

// Add inserts an item into the filter.
func (bf *BloomFilter) Add(item string) {
	h1, h2 := bf.baseHashes(item)

	bf.mu.Lock()
	for i := uint32(0); i < bf.numHash; i++ {
		pos := (h1 + uint64(i)*h2) % bf.size
		bf.bits[pos/64] |= 1 << (pos % 64)
	}
	bf.count++
	bf.mu.Unlock()
}

// Contains reports whether the item is possibly in the set.
// A false return is definitive; a true return may be a false positive.
func (bf *BloomFilter) Contains(item string) bool {
	h1, h2 := bf.baseHashes(item)

	bf.mu.RLock()
	defer bf.mu.RUnlock()

	for i := uint32(0); i < bf.numHash; i++ {
		pos := (h1 + uint64(i)*h2) % bf.size
		if bf.bits[pos/64]&(1<<(pos%64)) == 0 {
			return false
		}
	}
	return true
}

// Reset clears all bits and resets the item count.
func (bf *BloomFilter) Reset() {
	bf.mu.Lock()
	for i := range bf.bits {
		bf.bits[i] = 0
	}
	bf.count = 0
	bf.mu.Unlock()
}

// Count returns the number of items that have been added.
func (bf *BloomFilter) Count() uint64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.count
}

// FalsePositiveRate returns the theoretical false-positive probability
// at the current load: (1 - e^(-kn/m))^k.
func (bf *BloomFilter) FalsePositiveRate() float64 {
	bf.mu.RLock()
	n := float64(bf.count)
	bf.mu.RUnlock()

	k := float64(bf.numHash)
	m := float64(bf.size)
	return math.Pow(1-math.Exp(-k*n/m), k)
}

// baseHashes computes two independent 64-bit hashes using FNV-1a.
// These serve as the basis for double-hashing: h(i) = h1 + i*h2.
func (bf *BloomFilter) baseHashes(item string) (uint64, uint64) {
	var hasher hash.Hash64 = fnv.New64a()
	hasher.Write([]byte(item))
	h1 := hasher.Sum64()

	hasher.Reset()
	hasher.Write([]byte(item))
	hasher.Write([]byte{0xff, 0x9b, 0x6c, 0x3a})
	h2 := hasher.Sum64()

	if h2 == 0 {
		h2 = 1
	}
	return h1, h2
}
