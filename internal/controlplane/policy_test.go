package controlplane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeTestPolicyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "yara-exploits.tar.gz")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name: "exploit.yar",
		Mode: 0o644,
		Size: int64(len("rule test {}")),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("rule test {}")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	payload := buf.Bytes()
	sum := sha256.Sum256(payload)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	if err := os.WriteFile(bundlePath, payload, 0o640); err != nil {
		t.Fatal(err)
	}

	manifest := policyManifest{
		Bundles: []policyBundleMeta{{
			Name:    "yara-exploits",
			Version: "1.0.0",
			Format:  "tar.gz",
			File:    "yara-exploits.tar.gz",
			Hash:    hash,
		}},
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPolicyStoreGetPolicy(t *testing.T) {
	t.Parallel()

	dir := writeTestPolicyDir(t)
	store, err := NewPolicyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if store.PolicyHash() == "" {
		t.Fatal("expected policy hash")
	}

	unchanged := store.GetPolicy(store.PolicyHash())
	if unchanged.GetChanged() {
		t.Fatal("expected unchanged policy")
	}

	changed := store.GetPolicy("")
	if !changed.GetChanged() {
		t.Fatal("expected changed policy")
	}
	if len(changed.GetRuleBundles()) != 1 {
		t.Fatalf("bundles = %d want 1", len(changed.GetRuleBundles()))
	}
	if changed.GetRuleBundles()[0].GetName() != "yara-exploits" {
		t.Fatalf("bundle name = %q", changed.GetRuleBundles()[0].GetName())
	}
}

func TestPolicyStoreSignaturePassthrough(t *testing.T) {
	t.Parallel()

	dir := writeTestPolicyDir(t)
	manifestPath := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest policyManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Bundles[0].Signature = "deadbeef"
	raw, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, raw, 0o640); err != nil {
		t.Fatal(err)
	}

	store, err := NewPolicyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	resp := store.GetPolicy("")
	if resp.GetRuleBundles()[0].GetSignature() != "deadbeef" {
		t.Fatalf("signature = %q want deadbeef", resp.GetRuleBundles()[0].GetSignature())
	}
}
