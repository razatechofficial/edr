package comms

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func testPolicyKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "policy.pub.pem")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	return pub, priv, pubPath
}

func TestVerifyRuleBundleHashAndSignature(t *testing.T) {
	t.Parallel()

	data := []byte("tar.gz payload")
	sum := sha256.Sum256(data)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	_, priv, pubPath := testPolicyKeypair(t)
	sig := SignRuleBundle(data, priv)

	if err := VerifyRuleBundle("test", data, hash, sig, pubPath); err != nil {
		t.Fatalf("expected valid bundle: %v", err)
	}
}

func TestVerifyRuleBundleRejectsBadSignature(t *testing.T) {
	t.Parallel()

	data := []byte("tar.gz payload")
	sum := sha256.Sum256(data)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	_, priv, pubPath := testPolicyKeypair(t)
	sig := SignRuleBundle([]byte("other"), priv)

	if err := VerifyRuleBundle("test", data, hash, sig, pubPath); err == nil {
		t.Fatal("expected signature failure")
	}
}

func TestVerifyRuleBundleRequiresSignatureWhenPubKeySet(t *testing.T) {
	t.Parallel()

	data := []byte("tar.gz payload")
	sum := sha256.Sum256(data)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	_, _, pubPath := testPolicyKeypair(t)

	if err := VerifyRuleBundle("test", data, hash, "", pubPath); err == nil {
		t.Fatal("expected missing signature error")
	}
}

func TestVerifyRuleBundleSkipsSignatureWithoutPubKey(t *testing.T) {
	t.Parallel()

	data := []byte("tar.gz payload")
	sum := sha256.Sum256(data)
	hash := "sha256:" + hex.EncodeToString(sum[:])

	if err := VerifyRuleBundle("test", data, hash, "", ""); err != nil {
		t.Fatalf("expected hash-only verification: %v", err)
	}
}
