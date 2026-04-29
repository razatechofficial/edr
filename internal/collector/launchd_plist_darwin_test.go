//go:build darwin

package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const samplePlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.persist</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>/Users/foo/.config/payload.py</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
`

func TestLaunchdPlistSource_DetectsNewAndChangedFiles(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "com.example.persist.plist")
	if err := os.WriteFile(path, []byte(samplePlist), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	src := NewLaunchdPlistSource("ep", "host")
	src.setRoots(tmp)

	first, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("expected 1 emit, got %d", len(first))
	}
	if first[0].Process == nil || first[0].Process.CommandLine != "com.example.persist" {
		t.Fatalf("label not parsed: %+v", first[0].Process)
	}
	if first[0].Process.ProcessPath == "" {
		t.Fatalf("program not parsed: %+v", first[0].Process)
	}

	// Second snapshot with no change must emit nothing.
	second, _ := src.Snapshot(context.Background())
	if len(second) != 0 {
		t.Fatalf("expected 0 emits on no-change, got %d", len(second))
	}
}

func TestLaunchdPlistSource_HealthShape(t *testing.T) {
	src := NewLaunchdPlistSource("ep", "host")
	_, _ = src.Snapshot(context.Background())
	h := src.ExportMonitoringHealth()
	if h["source"] != "launchd-plist" || h["name"] != "persistence" {
		t.Fatalf("unexpected health: %v", h)
	}
}
