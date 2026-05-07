//go:build darwin && cgo && !nosec

package collector

import (
	"context"
	"testing"
)

func TestRunSCDynamicStoreRouteProbe_UsesCGOStreamResult(t *testing.T) {
	old := scdsWatchOnceFn
	defer func() { scdsWatchOnceFn = old }()
	scdsWatchOnceFn = func(seconds float64) (string, int, int) {
		if seconds <= 0 {
			t.Fatalf("expected positive watch duration")
		}
		return "State:/Network/Global/IPv4", 3, 0
	}
	var got map[string]any
	RunSCDynamicStoreRouteProbe(context.Background(), func(m map[string]any) { got = m })
	if got == nil {
		t.Fatal("expected probe output")
	}
	if got["scdynamicstore_probe"] != "cgo_stream" {
		t.Fatalf("unexpected probe output: %#v", got)
	}
	if got["scdynamicstore_stream_active"] != true {
		t.Fatalf("expected stream active: %#v", got)
	}
	if got["scdynamicstore_last_key"] != "State:/Network/Global/IPv4" {
		t.Fatalf("unexpected key: %#v", got)
	}
}

