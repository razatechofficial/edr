package rules

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadVerified loads rules YAML and optionally verifies a detached Ed25519 signature
// in path+".sig" (raw 64-byte signature) against the public key PEM at pubKeyPath.
// If pubKeyPath is empty, behaves like Load.
func LoadVerified(path, pubKeyPath string) (RuleSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RuleSet{}, err
	}
	if pubKeyPath != "" {
		sig, err := os.ReadFile(path + ".sig")
		if err != nil {
			return RuleSet{}, err
		}
		pubPEM, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return RuleSet{}, err
		}
		pub, err := parseEd25519PublicKey(pubPEM)
		if err != nil {
			return RuleSet{}, err
		}
		if !ed25519.Verify(pub, b, sig) {
			return RuleSet{}, errors.New("rules signature verification failed")
		}
	}
	var rs RuleSet
	if err := yaml.Unmarshal(b, &rs); err != nil {
		return RuleSet{}, err
	}
	return rs, nil
}

func parseEd25519PublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("rules pubkey: invalid PEM")
	}
	raw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := raw.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("rules pubkey: expected Ed25519")
	}
	return pub, nil
}
