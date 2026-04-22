package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFileQuarantine_RoundTrip(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	fpath := filepath.Join(tmp, "bad.exe")
	content := []byte("malware-bytes")
	if err := os.WriteFile(fpath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(content)
	wantHash := hex.EncodeToString(h[:])

	qdir := filepath.Join(tmp, "q")
	act := &FileQuarantineAction{Path: fpath, QuarantineDir: qdir, DetectionID: "det-1"}
	rollback, err := act.Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fpath); !os.IsNotExist(err) {
		t.Fatal("original should be gone")
	}
	dest := filepath.Join(qdir, wantHash, "bad.exe")
	if _, err := os.Stat(dest); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(qdir, wantHash, wantHash+".meta.json"))
	var m QuarantineMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.SHA256 != wantHash {
		t.Fatalf("hash %q", m.SHA256)
	}
	if m.OriginalPath == "" {
		t.Fatal("original path")
	}
	if rollback == nil {
		t.Fatal("expected rollback")
	}
	if err := rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(fpath); err != nil || st.Size() == 0 {
		t.Fatalf("restore failed: %v", err)
	}
}

func TestFileQuarantine_RejectSymlink(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	target := filepath.Join(tmp, "real")
	_ = os.WriteFile(target, []byte("x"), 0o600)
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	act := &FileQuarantineAction{Path: link, QuarantineDir: filepath.Join(tmp, "q"), DetectionID: "d"}
	_, err := act.Execute(context.Background())
	if err == nil {
		t.Fatal("expected error for symlink")
	}
}
