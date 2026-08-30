package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestExtraPurgeTreesNeverRoot(t *testing.T) {
	for _, p := range extraPurgeTrees() {
		if stringsBlankOrRoot(p) {
			t.Fatalf("refusing to purge %q", p)
		}
	}
}

func TestStringsBlankOrRoot(t *testing.T) {
	if !stringsBlankOrRoot("/") || !stringsBlankOrRoot("") {
		t.Fatal("root/empty must be rejected")
	}
	if stringsBlankOrRoot("/usr/local/libexec/edr-agent.app") {
		t.Fatal("product path must be allowed")
	}
}

func TestDarwinExtraIncludesLibexec(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip()
	}
	found := false
	for _, p := range extraPurgeTrees() {
		if strings.Contains(p, "libexec") {
			found = true
		}
	}
	if !found {
		t.Fatal("macOS uninstall must remove /usr/local/libexec/edr-agent.app")
	}
}
