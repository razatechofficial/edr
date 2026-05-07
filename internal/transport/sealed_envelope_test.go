package transport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAESGCMSealer_roundTrip(t *testing.T) {
	dir := t.TempDir()
	kp := filepath.Join(dir, "key.bin")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(kp, key, 0o600); err != nil {
		t.Fatal(err)
	}
	seal, err := AESGCMSealer(kp, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"hello":"world"}`)
	out, err := seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnsealV1(out, kp)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}
