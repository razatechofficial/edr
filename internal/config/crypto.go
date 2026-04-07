package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2Iterations = 100_000
	keyLen           = 32 // AES-256
	saltLen          = 32
)

// EncryptConfig encrypts plaintext using AES-256-GCM with the provided
// 32-byte key. The returned ciphertext has the GCM nonce prepended.
func EncryptConfig(plaintext, key []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("key must be %d bytes for AES-256, got %d", keyLen, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptConfig decrypts AES-256-GCM ciphertext produced by EncryptConfig.
// The ciphertext must begin with the GCM nonce.
func DecryptConfig(ciphertext, key []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("key must be %d bytes for AES-256, got %d", keyLen, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes (nonce requires %d)", len(ciphertext), nonceSize)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// DeriveKey derives a 32-byte AES-256 key from a passphrase and salt using
// PBKDF2 with SHA-256 and 100 000 iterations.
func DeriveKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iterations, keyLen, sha256.New)
}

// GenerateSalt returns 32 cryptographically secure random bytes suitable for
// use as a PBKDF2 salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	return salt, nil
}

// DeriveHardwareBoundKey derives a key material candidate using host-bound
// attributes and a caller secret. This is a software fallback for TPM-bound
// environments and can be rotated by changing the epoch.
func DeriveHardwareBoundKey(secret string, epoch int64) []byte {
	host, _ := os.Hostname()
	material := fmt.Sprintf("%s|%s|%d|%s", host, runtimeOSArch(), epoch, secret)
	sum := sha256.Sum256([]byte(material))
	return sum[:]
}

// RotateKey derives a fresh key using the current UTC day as epoch.
func RotateKey(secret string) []byte {
	epoch := time.Now().UTC().Unix() / 86400
	return DeriveHardwareBoundKey(secret, epoch)
}

func runtimeOSArch() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}
