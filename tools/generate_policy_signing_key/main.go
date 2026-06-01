// Command generate_policy_signing_key creates an Ed25519 keypair for signing
// control plane policy bundles (EDR_POLICY_SIGN_KEY / policy_verify_pubkey_path).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	outDir := flag.String("out", ".", "output directory for key files")
	seedName := flag.String("seed", "edr-policy.seed", "private seed filename (hex, mode 0600)")
	pubName := flag.String("pub", "edr-policy.pub.pem", "public key PEM filename")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		fatal("mkdir: %v", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		fatal("generate seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	seedPath := filepath.Join(*outDir, *seedName)
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		fatal("write seed: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fatal("marshal pubkey: %v", err)
	}
	pubPath := filepath.Join(*outDir, *pubName)
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}), 0o644); err != nil {
		fatal("write pubkey: %v", err)
	}

	fmt.Printf("policy signing seed: %s\n", seedPath)
	fmt.Printf("policy verify pubkey: %s\n", pubPath)
	fmt.Println("deploy pubkey to agents as policy_verify_pubkey_path")
	fmt.Println("stage signed bundles with: export EDR_POLICY_SIGN_KEY=" + seedPath)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
