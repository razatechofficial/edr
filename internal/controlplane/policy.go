package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/razatechofficial/edr/pkg/protocol"
)

type policyBundleMeta struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Format    string `json:"format"`
	File      string `json:"file"`
	Hash      string `json:"hash"`
	Signature string `json:"signature,omitempty"`
}

type policyManifest struct {
	Bundles []policyBundleMeta `json:"bundles"`
}

// PolicyStore serves detection rule bundles from a on-disk policy directory.
type PolicyStore struct {
	dir string

	mu       sync.RWMutex
	hash     string
	manifest policyManifest
	data     map[string][]byte
}

// NewPolicyStore loads policy bundles from dir (manifest.json + bundle files).
func NewPolicyStore(dir string) (*PolicyStore, error) {
	store := &PolicyStore{dir: dir}
	if err := store.Reload(); err != nil {
		return nil, err
	}
	return store, nil
}

// Reload re-reads manifest.json and bundle payloads from disk.
func (p *PolicyStore) Reload() error {
	if p == nil {
		return fmt.Errorf("policy_store: nil store")
	}
	manifestPath := filepath.Join(p.dir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			p.mu.Lock()
			p.hash = ""
			p.manifest = policyManifest{}
			p.data = nil
			p.mu.Unlock()
			return nil
		}
		return fmt.Errorf("policy_store: read manifest: %w", err)
	}

	var manifest policyManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("policy_store: parse manifest: %w", err)
	}

	data := make(map[string][]byte, len(manifest.Bundles))
	for _, bundle := range manifest.Bundles {
		if bundle.Name == "" || bundle.File == "" {
			return fmt.Errorf("policy_store: bundle missing name or file")
		}
		path := filepath.Join(p.dir, bundle.File)
		payload, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("policy_store: read bundle %q: %w", bundle.Name, err)
		}
		if bundle.Hash != "" {
			sum := sha256.Sum256(payload)
			got := "sha256:" + hex.EncodeToString(sum[:])
			if got != bundle.Hash {
				return fmt.Errorf("policy_store: bundle %q hash mismatch", bundle.Name)
			}
		}
		data[bundle.Name] = payload
	}

	sum := sha256.Sum256(raw)
	p.mu.Lock()
	p.hash = hex.EncodeToString(sum[:])
	p.manifest = manifest
	p.data = data
	p.mu.Unlock()
	return nil
}

// PolicyHash returns the hash of the current manifest, or empty when unset.
func (p *PolicyStore) PolicyHash() string {
	if p == nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.hash
}

// AdminSummary returns a JSON-friendly policy view without bundle payloads.
func (p *PolicyStore) AdminSummary() map[string]any {
	if p == nil {
		return map[string]any{"policy_hash": "", "bundles": []any{}}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	bundles := make([]map[string]string, 0, len(p.manifest.Bundles))
	for _, bundle := range p.manifest.Bundles {
		bundles = append(bundles, map[string]string{
			"name":      bundle.Name,
			"version":   bundle.Version,
			"format":    bundle.Format,
			"hash":      bundle.Hash,
			"file":      bundle.File,
			"signature": bundle.Signature,
		})
	}
	return map[string]any{
		"policy_hash": p.hash,
		"bundles":     bundles,
	}
}

// GetPolicy builds a gRPC policy response for an agent.
func (p *PolicyStore) GetPolicy(currentHash string) *protocol.PolicyResponse {
	if p == nil || p.PolicyHash() == "" {
		return &protocol.PolicyResponse{
			PolicyHash: "local-default",
			Changed:    false,
		}
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if currentHash != "" && currentHash == p.hash {
		return &protocol.PolicyResponse{
			PolicyHash: p.hash,
			Changed:    false,
		}
	}

	out := make([]*protocol.RuleBundle, 0, len(p.manifest.Bundles))
	for _, bundle := range p.manifest.Bundles {
		out = append(out, &protocol.RuleBundle{
			Name:      bundle.Name,
			Version:   bundle.Version,
			Format:    bundle.Format,
			Data:      append([]byte(nil), p.data[bundle.Name]...),
			Hash:      bundle.Hash,
			Signature: bundle.Signature,
		})
	}

	return &protocol.PolicyResponse{
		PolicyHash:  p.hash,
		Changed:     true,
		RuleBundles: out,
		Detection: &protocol.DetectionPolicy{
			SigmaEnabled:      true,
			YaraEnabled:       true,
			IocEnabled:        true,
			BehavioralEnabled: true,
		},
		Response: &protocol.ResponsePolicy{
			AutoResponse: false,
		},
	}
}
