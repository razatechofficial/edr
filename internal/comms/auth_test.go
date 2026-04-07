package comms

import "testing"

func TestEqualBytes(t *testing.T) {
	t.Parallel()
	if !equalBytes([]byte("abc"), []byte("abc")) {
		t.Fatalf("equal bytes should match")
	}
	if equalBytes([]byte("abc"), []byte("abd")) {
		t.Fatalf("different bytes should not match")
	}
}
