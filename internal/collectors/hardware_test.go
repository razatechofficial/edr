//go:build linux

package collectors

import (
	"testing"

	"go.uber.org/zap"
)

func TestHardwareCollectorName(t *testing.T) {
	t.Parallel()
	c := NewHardwareCollector(zap.NewNop())
	if got := c.Name(); got != "hardware" {
		t.Errorf("Name() = %q, want %q", got, "hardware")
	}
}
