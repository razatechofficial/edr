// Command sign_policy_bundle signs a control plane rule bundle with Ed25519.
//
// Output is a hex-encoded signature over the raw bundle bytes, suitable for
// manifest.json and gRPC RuleBundle.signature fields.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/razatechofficial/edr/internal/comms"
)

func main() {
	keyArg := flag.String("key", "", "Ed25519 private key as hex (32-byte seed or 64-byte private key) or path to hex file")
	flag.Parse()
	if *keyArg == "" {
		fatal("--key is required")
	}
	if flag.NArg() != 1 {
		fatal("usage: sign_policy_bundle -key <hex-or-path> <bundle.tar.gz>")
	}

	priv, err := loadPrivateKey(*keyArg)
	if err != nil {
		fatal("load key: %v", err)
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fatal("read bundle: %v", err)
	}
	fmt.Print(comms.SignRuleBundle(data, priv))
}

func loadPrivateKey(arg string) (ed25519.PrivateKey, error) {
	candidates := []string{arg}
	if info, err := os.Stat(arg); err == nil && !info.IsDir() {
		b, err := os.ReadFile(arg)
		if err != nil {
			return nil, err
		}
		candidates = []string{string(b)}
	}
	for _, c := range candidates {
		trimmed := trimWhitespace(c)
		if b, err := hex.DecodeString(trimmed); err == nil {
			switch len(b) {
			case ed25519.PrivateKeySize:
				return ed25519.PrivateKey(b), nil
			case ed25519.SeedSize:
				return ed25519.NewKeyFromSeed(b), nil
			}
		}
	}
	return nil, fmt.Errorf("unrecognised key format (need 32-byte seed or 64-byte private key, hex)")
}

func trimWhitespace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r':
		return true
	}
	return false
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
