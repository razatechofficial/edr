package ioc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func BenchmarkHashDBLookup(b *testing.B) {
	db := NewHashDB()
	hashes := make([]string, 10_000)
	for i := range hashes {
		h := sha256.Sum256([]byte(fmt.Sprintf("malware-%d", i)))
		hashes[i] = hex.EncodeToString(h[:])
		db.Add(HashEntry{Hash: hashes[i], Type: HashSHA256})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.Lookup(hashes[i%len(hashes)])
	}
}

func BenchmarkHashDBLookupWithBloom(b *testing.B) {
	db := NewHashDB()
	hashes := make([]string, 10_000)
	for i := range hashes {
		h := sha256.Sum256([]byte(fmt.Sprintf("malware-%d", i)))
		hashes[i] = hex.EncodeToString(h[:])
		db.Add(HashEntry{Hash: hashes[i], Type: HashSHA256})
	}

	misses := make([]string, 10_000)
	for i := range misses {
		h := sha256.Sum256([]byte(fmt.Sprintf("clean-%d", i)))
		misses[i] = hex.EncodeToString(h[:])
	}

	b.Run("hit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.Lookup(hashes[i%len(hashes)])
		}
	})

	b.Run("miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.Lookup(misses[i%len(misses)])
		}
	})
}
