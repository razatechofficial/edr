//go:build linux

package collector

import (
	"context"
	"os"
	"testing"
)

func TestBuildSocketInodeToPIDMapNonPanic(t *testing.T) {
	m := buildSocketInodeToPIDMap(context.Background(), nil)
	if m == nil {
		t.Fatal("nil map")
	}
	// On typical Linux there is at least the agent's own socket inode; allow empty in sandboxes.
	_ = os.Getpid()
	if len(m) == 0 {
		t.Log("empty inode map (sandbox without readable /proc/*/fd)")
	}
}
