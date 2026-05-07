package forensics

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyFileBounded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "in.bin")
	if err := os.WriteFile(src, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	dstDir := filepath.Join(dir, "out")
	ent, err := copyFileBounded(src, dstDir, "copy.bin", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !ent.Copied || ent.SHA256 == "" || ent.Size != 3 {
		t.Fatalf("%+v", ent)
	}
	_, err = copyFileBounded(src, dstDir, "huge.bin", 1)
	if err == nil {
		t.Fatal("expected oversize error")
	}
}
