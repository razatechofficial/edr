package config

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("agent:\n  id: test-agent\n  log_level: info\n")

	ciphertext, err := EncryptConfig(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptConfig: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := DecryptConfig(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptConfig: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	t.Parallel()
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}

	ciphertext, err := EncryptConfig([]byte("secret data"), key1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptConfig(ciphertext, key2)
	if err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	ciphertext, err := EncryptConfig([]byte("sensitive config data"), key)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext[len(ciphertext)/2] ^= 0xFF

	_, err = DecryptConfig(ciphertext, key)
	if err == nil {
		t.Fatal("expected GCM authentication failure with tampered ciphertext")
	}
}

func TestDeriveKey(t *testing.T) {
	t.Parallel()
	salt := []byte("fixed-salt-for-testing-32-bytes!")

	k1 := DeriveKey("my-passphrase", salt)
	k2 := DeriveKey("my-passphrase", salt)

	if len(k1) != 32 {
		t.Errorf("key length = %d, want 32", len(k1))
	}
	if !bytes.Equal(k1, k2) {
		t.Error("same passphrase + salt should produce identical keys")
	}
}

func TestDeriveKeyDifferentSalt(t *testing.T) {
	t.Parallel()
	salt1 := []byte("salt-one-for-testing-32-bytes!!")
	salt2 := []byte("salt-two-for-testing-32-bytes!!")

	k1 := DeriveKey("same-passphrase", salt1)
	k2 := DeriveKey("same-passphrase", salt2)

	if bytes.Equal(k1, k2) {
		t.Error("different salts should produce different keys")
	}
}

func TestGenerateSalt(t *testing.T) {
	t.Parallel()
	s1, err := GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(s1) != 32 {
		t.Errorf("salt length = %d, want 32", len(s1))
	}

	s2, err := GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s1, s2) {
		t.Error("two GenerateSalt calls should produce different salts")
	}
}
