//go:build windows

package kernel

import (
	"testing"
)

func TestETWDriver_RecoverState_DefaultActive(t *testing.T) {
	t.Parallel()
	d, err := NewETWDriver("test")
	if err != nil {
		t.Fatal(err)
	}
	if d.ETWRecoverState() != "active" {
		t.Fatalf("state=%q", d.ETWRecoverState())
	}
}
