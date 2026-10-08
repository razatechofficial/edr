package comms

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// VerifyRuleBundle checks a rule bundle before it is written to disk.
//
// A bundle is executable content in everything but name: it lands in the tree
// the Sigma, YARA and SCA loaders read, and an SCA rule of type `c:` runs an
// arbitrary binary as root. Accepting one whose origin cannot be proven is
// therefore equivalent to accepting code from whoever is on the other end of
// the connection — which, on a deployment without mutual TLS, is anybody on the
// network path.
//
// So an unconfigured signing key fails closed. allowUnsigned exists for
// development and for operators who have deliberately accepted the risk, and it
// still requires a hash so that at least corruption is caught.
func VerifyRuleBundle(name string, data []byte, hash, signature, pubKeyPath string, allowUnsigned bool) error {
	if len(data) == 0 {
		return fmt.Errorf("rule_bundle %q: empty payload", name)
	}
	if err := verifyRuleBundleHash(name, data, hash); err != nil {
		return err
	}
	pubKeyPath = strings.TrimSpace(pubKeyPath)
	if pubKeyPath == "" {
		if !allowUnsigned {
			return fmt.Errorf(
				"rule_bundle %q: refused because no signing key is configured; "+
					"set policy_verify_pubkey_path, or set rules_allow_unsigned to accept unverified rule content",
				name)
		}
		if strings.TrimSpace(hash) == "" {
			return fmt.Errorf("rule_bundle %q: refused because it carries neither a signature nor a hash", name)
		}
		return nil
	}
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return fmt.Errorf("rule_bundle %q: signature required when policy_verify_pubkey_path is set", name)
	}
	pub, err := loadEd25519PublicKey(pubKeyPath)
	if err != nil {
		return fmt.Errorf("rule_bundle %q: %w", name, err)
	}
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("rule_bundle %q: decode signature: %w", name, err)
	}
	if !ed25519.Verify(pub, data, sigBytes) {
		return fmt.Errorf("rule_bundle %q: signature verification failed", name)
	}
	return nil
}

// SignRuleBundle returns a hex-encoded Ed25519 signature over raw bundle bytes.
func SignRuleBundle(data []byte, priv ed25519.PrivateKey) string {
	return hex.EncodeToString(ed25519.Sign(priv, data))
}

func verifyRuleBundleHash(name string, data []byte, hash string) error {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return nil
	}
	sum := sha256.Sum256(data)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != hash {
		return fmt.Errorf("rule_bundle %q: hash mismatch", name)
	}
	return nil
}

func loadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy pubkey %s: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("policy pubkey: invalid PEM")
	}
	raw, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("policy pubkey: %w", err)
	}
	pub, ok := raw.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("policy pubkey: expected Ed25519")
	}
	return pub, nil
}
