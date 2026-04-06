package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/user"
	"strconv"
	"testing"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

func TestProcessCollectorName(t *testing.T) {
	t.Parallel()
	c := NewProcessCollector(zap.NewNop())
	if got := c.Name(); got != "process" {
		t.Errorf("Name() = %q, want %q", got, "process")
	}
}

func TestProcessCollectorEventTypes(t *testing.T) {
	t.Parallel()
	c := NewProcessCollector(zap.NewNop())
	types := c.EventTypes()

	if len(types) != 1 {
		t.Fatalf("EventTypes() len = %d, want 1", len(types))
	}
	if types[0] != events.EventProcess {
		t.Errorf("EventTypes()[0] = %q, want %q", types[0], events.EventProcess)
	}
}

func TestSHA256HashFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/testbin"

	content := []byte("known content for hashing")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	got, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}

	h := sha256.Sum256(content)
	want := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("hashFile = %q, want %q", got, want)
	}
}

func TestBuildProcessTree(t *testing.T) {
	t.Parallel()
	c := NewProcessCollector(zap.NewNop())

	c.mu.Lock()
	c.tree[100] = &processInfo{
		pid:     100,
		ppid:    1,
		comm:    "bash",
		exePath: "/usr/bin/bash",
		uid:     1000,
	}
	c.tree[200] = &processInfo{
		pid:     200,
		ppid:    100,
		comm:    "python",
		exePath: "/usr/bin/python3",
		uid:     1000,
	}
	c.mu.Unlock()

	parentComm := c.lookupComm(100)
	if parentComm != "bash" {
		t.Errorf("parent comm = %q, want %q", parentComm, "bash")
	}

	childComm := c.lookupComm(200)
	if childComm != "python" {
		t.Errorf("child comm = %q, want %q", childComm, "python")
	}

	c.mu.RLock()
	child, ok := c.tree[200]
	c.mu.RUnlock()
	if !ok {
		t.Fatal("child PID 200 not found in tree")
	}
	if child.ppid != 100 {
		t.Errorf("child.ppid = %d, want 100", child.ppid)
	}

	unknown := c.lookupComm(9999)
	if unknown != "" {
		t.Errorf("lookupComm for unknown PID = %q, want empty", unknown)
	}
}

func TestUserResolution(t *testing.T) {
	t.Parallel()
	uid := uint32(os.Getuid())
	result := resolveUser(uid)

	u, err := user.Current()
	if err != nil {
		t.Skipf("cannot determine current user: %v", err)
	}
	if result != u.Username {
		t.Errorf("resolveUser(%d) = %q, want %q", uid, result, u.Username)
	}

	bogus := resolveUser(99999)
	if _, err := strconv.Atoi(bogus); err != nil {
		// If the UID doesn't resolve, it should fall back to the numeric string.
		// Some systems may have UID 99999 assigned, so only check if it's non-empty.
		if bogus == "" {
			t.Error("resolveUser for bogus UID should return non-empty string")
		}
	}
}
