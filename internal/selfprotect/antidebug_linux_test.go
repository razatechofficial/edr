//go:build linux

package selfprotect

import (
	"testing"
)

func TestAntiDebugPosture_MapShape(t *testing.T) {
	t.Parallel()
	p := AntiDebugPosture()
	if _, ok := p["tracer_attached"]; !ok {
		t.Fatal("missing tracer_attached")
	}
	if _, ok := p["ld_preload_set"]; !ok {
		t.Fatal("missing ld_preload_set")
	}
	if _, ok := p["ld_debug_set"]; !ok {
		t.Fatal("missing ld_debug_set")
	}
	if _, hasDump := p["dumpable"]; !hasDump {
		if _, hasErr := p["dumpable_error"]; !hasErr {
			t.Fatal("expected dumpable or dumpable_error")
		}
	}
}
