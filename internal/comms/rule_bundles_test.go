package comms

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func buildTestBundle(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, body := range members {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestApplyRuleBundleTarGz(t *testing.T) {
	t.Parallel()

	dest := t.TempDir()
	data := buildTestBundle(t, map[string]string{
		"yara/exploits/test.yar": "rule test { condition: true }",
	})
	if err := ApplyRuleBundleTarGz("yara-exploits", data, dest); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dest, "yara", "exploits", "test.yar")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("missing extracted file: %v", err)
	}
}

func TestApplyRuleBundleTarGzRejectsTraversal(t *testing.T) {
	t.Parallel()

	dest := t.TempDir()
	data := buildTestBundle(t, map[string]string{
		"../escape.yar": "rule bad { condition: true }",
	})
	if err := ApplyRuleBundleTarGz("bad", data, dest); err == nil {
		t.Fatal("expected traversal error")
	}
}
