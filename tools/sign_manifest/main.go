// Command sign_manifest produces a signed integrity manifest for the
// EDR agent. It is intended to run from the release pipeline as a
// generate step (e.g. `make generate-manifest`).
//
// Inputs:
//   - One or more file paths to include in the manifest. Each is hashed
//     with SHA-256 and recorded as path -> hex digest.
//   - An Ed25519 private signing key (PEM or hex). The matching public
//     key must be baked into the agent binary via the
//     embeddedManifestPublicKey ldflags var.
//
// Output:
//   - A JSON file at -output with the canonical manifest plus an
//     Ed25519 signature over the canonical form (Files map sorted,
//     omitted signature field) so the agent can verify it at startup.
//
// The tool is intentionally small and dependency-free so it can run in
// a hardened, network-isolated signing environment.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

type manifest struct {
	Version   string            `json:"version"`
	BuildTime string            `json:"build_time"`
	Files     map[string]string `json:"files"`
	Signature string            `json:"signature"`
}

type canonical struct {
	Version   string            `json:"version"`
	BuildTime string            `json:"build_time"`
	Files     map[string]string `json:"files"`
}

func main() {
	var (
		keyArg   = flag.String("key", "", "Ed25519 private signing key as hex (64 bytes / 128 chars) or path to a file containing hex")
		outArg   = flag.String("output", "internal/selfprotect/integrity_manifest.json", "output manifest path")
		versArg  = flag.String("version", "dev", "manifest version (typically the release tag)")
	)
	flag.Parse()
	inputs := flag.Args()

	if *keyArg == "" {
		fatal("--key is required")
	}
	if len(inputs) == 0 {
		fatal("at least one file path to sign is required")
	}

	priv, err := loadPrivateKey(*keyArg)
	if err != nil {
		fatal("load key: %v", err)
	}

	files := map[string]string{}
	for _, p := range inputs {
		h, err := hashFile(p)
		if err != nil {
			fatal("hash %s: %v", p, err)
		}
		files[p] = h
	}

	m := manifest{
		Version:   *versArg,
		BuildTime: time.Now().UTC().Format(time.RFC3339),
		Files:     files,
	}

	canon, err := json.Marshal(canonical{
		Version:   m.Version,
		BuildTime: m.BuildTime,
		Files:     sortedMap(m.Files),
	})
	if err != nil {
		fatal("canonical marshal: %v", err)
	}
	sig := ed25519.Sign(priv, canon)
	m.Signature = hex.EncodeToString(sig)

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fatal("marshal output: %v", err)
	}
	if err := os.WriteFile(*outArg, append(out, '\n'), 0o644); err != nil {
		fatal("write %s: %v", *outArg, err)
	}
	fmt.Fprintf(os.Stdout, "wrote %s with %d files\n", *outArg, len(files))
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

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sortedMap(m map[string]string) map[string]string {
	// json.Marshal already sorts map keys; this returns a copy purely
	// for clarity at the call site.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(m))
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
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
