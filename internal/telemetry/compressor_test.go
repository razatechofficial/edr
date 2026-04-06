package telemetry

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCompressDecompressRoundTrip(t *testing.T) {
	t.Parallel()
	original := []byte("the quick brown fox jumps over the lazy dog — repeated many times for compression")
	original = bytes.Repeat(original, 50)

	compressed, err := Compress(original)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	if len(compressed) >= len(original) {
		t.Logf("warning: compressed size %d >= original %d (may happen for small data)", len(compressed), len(original))
	}

	decompressed, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(decompressed, original) {
		t.Fatalf("round-trip mismatch: decompressed length %d, original length %d", len(decompressed), len(original))
	}
}

func TestCompressSmallData(t *testing.T) {
	t.Parallel()
	original := []byte("hello")

	compressed, err := Compress(original)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	decompressed, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(decompressed, original) {
		t.Fatal("round-trip mismatch for small data")
	}
}

func TestCompressLargeData(t *testing.T) {
	t.Parallel()
	original := make([]byte, 1<<20) // 1MB
	if _, err := rand.Read(original); err != nil {
		t.Fatalf("generate random data: %v", err)
	}

	compressed, err := Compress(original)
	if err != nil {
		t.Fatalf("Compress 1MB: %v", err)
	}
	decompressed, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress 1MB: %v", err)
	}
	if !bytes.Equal(decompressed, original) {
		t.Fatal("round-trip mismatch for 1MB data")
	}
}

func TestCompressEmptyData(t *testing.T) {
	t.Parallel()
	compressed, err := Compress([]byte{})
	if err != nil {
		t.Fatalf("Compress empty: %v", err)
	}
	decompressed, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress empty: %v", err)
	}
	if len(decompressed) != 0 {
		t.Fatalf("expected empty decompressed, got %d bytes", len(decompressed))
	}
}
