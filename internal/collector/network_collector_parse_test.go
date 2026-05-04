package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProcNetRecordsInode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tcp")
	// Minimal /proc/net/tcp-style row: inode is fields[9] (0-based).
	content := "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		" 0: 0100007F:0019 020011AC:DE01 01 00000000:00000000 00:00000000 00000000     0        0 42424242 1 0000000000000000 100 0 0 10 -1\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	entries := parseProcNet(p, "tcp")
	if len(entries) != 1 {
		t.Fatalf("entries=%d want 1", len(entries))
	}
	if entries[0].inode != 42424242 {
		t.Fatalf("inode=%d want 42424242", entries[0].inode)
	}
}
