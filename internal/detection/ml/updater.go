package ml

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"sync"
)

// ModelManager handles model lifecycle including hot-swapping with optional
// Ed25519 signature verification.
type ModelManager struct {
	mu     sync.RWMutex
	models map[string]*ONNXSession
	pubKey ed25519.PublicKey
}

// NewModelManager creates a ModelManager. If pubKey is a valid Ed25519 public
// key (32 bytes), all Load and HotSwap operations will verify signatures.
// Pass nil to disable verification.
func NewModelManager(pubKey []byte) *ModelManager {
	var key ed25519.PublicKey
	if len(pubKey) == ed25519.PublicKeySize {
		key = ed25519.PublicKey(pubKey)
	}
	return &ModelManager{
		models: make(map[string]*ONNXSession),
		pubKey: key,
	}
}

// Load reads the ONNX model at path (verifying path+".sig" when a public key
// is configured), creates a session, and registers it under name. Any
// previously loaded model with the same name is closed.
func (m *ModelManager) Load(name, path string) error {
	if m.pubKey != nil {
		if err := m.verifyFile(path); err != nil {
			return err
		}
	}

	session, err := NewONNXSession(path)
	if err != nil {
		return fmt.Errorf("ml: load model %s: %w", name, err)
	}

	m.mu.Lock()
	old := m.models[name]
	m.models[name] = session
	m.mu.Unlock()

	if old != nil {
		old.Close()
	}
	return nil
}

// Get returns the session registered under name, or an error if not loaded.
func (m *ModelManager) Get(name string) (*ONNXSession, error) {
	m.mu.RLock()
	s, ok := m.models[name]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("model %q not loaded", name)
	}
	return s, nil
}

// HotSwap atomically replaces the model registered under name. The new model
// data and its detached Ed25519 signature are verified (when a public key is
// configured), written to a temporary file, loaded as a new session, and
// swapped in under a write lock. The old session is closed after the swap.
func (m *ModelManager) HotSwap(name string, newModelData []byte, signature []byte) error {
	if m.pubKey != nil {
		if !ed25519.Verify(m.pubKey, newModelData, signature) {
			return fmt.Errorf("ml: signature verification failed for model %s", name)
		}
	}

	tmp, err := os.CreateTemp("", "edr-model-*.onnx")
	if err != nil {
		return fmt.Errorf("ml: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(newModelData); err != nil {
		tmp.Close()
		return fmt.Errorf("ml: write temp model: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("ml: close temp model: %w", err)
	}

	newSession, err := NewONNXSession(tmpPath)
	if err != nil {
		return fmt.Errorf("ml: load replacement model %s: %w", name, err)
	}

	m.mu.Lock()
	old := m.models[name]
	m.models[name] = newSession
	m.mu.Unlock()

	if old != nil {
		old.Close()
	}
	return nil
}

// Count returns the number of currently loaded models.
func (m *ModelManager) Count() int {
	m.mu.RLock()
	n := len(m.models)
	m.mu.RUnlock()
	return n
}

// Close releases all loaded model sessions.
func (m *ModelManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, s := range m.models {
		s.Close()
		delete(m.models, name)
	}
}

func (m *ModelManager) verifyFile(path string) error {
	modelData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("ml: read model %s: %w", path, err)
	}
	sigData, err := os.ReadFile(path + ".sig")
	if err != nil {
		return fmt.Errorf("ml: read signature %s.sig: %w", path, err)
	}
	if !ed25519.Verify(m.pubKey, modelData, sigData) {
		return fmt.Errorf("ml: signature verification failed for %s", path)
	}
	return nil
}
