package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// SealedV1 is the on-wire JSON wrapper for AES-GCM sealed payloads.
type SealedV1 struct {
	V       int    `json:"v"`
	KeyID   string `json:"key_id,omitempty"`
	Nonce   string `json:"nonce"`   // base64 raw nonce
	Payload string `json:"payload"` // base64 ciphertext+tag
}

// AESGCMSealer returns a function that wraps plaintext JSON in SealedV1 using a 32-byte key file.
func AESGCMSealer(keyPath, keyID string) (func(plaintext []byte) ([]byte, error), error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if len(raw) < 32 {
		return nil, errors.New("seal key file must contain at least 32 bytes")
	}
	key := make([]byte, 32)
	copy(key, raw[:32])
	return func(plaintext []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
		ct := gcm.Seal(nil, nonce, plaintext, nil)
		env := SealedV1{
			V:       1,
			KeyID:   keyID,
			Nonce:   base64.StdEncoding.EncodeToString(nonce),
			Payload: base64.StdEncoding.EncodeToString(ct),
		}
		return json.Marshal(env)
	}, nil
}

// UnsealV1 decrypts a SealedV1 JSON blob (for tests and receiver-side tooling).
func UnsealV1(sealedJSON []byte, keyPath string) ([]byte, error) {
	var env SealedV1
	if err := json.Unmarshal(sealedJSON, &env); err != nil {
		return nil, err
	}
	if env.V != 1 {
		return nil, fmt.Errorf("unsupported sealed version %d", env.V)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	copy(key, raw[:32])
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}
