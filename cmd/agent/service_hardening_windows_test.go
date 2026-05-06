//go:build windows

package main

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
)

func TestApplyWindowsServiceHardening_DisabledByConfig(t *testing.T) {
	t.Parallel()
	c := config.Defaults()
	c.Monitoring.WindowsServiceHardening = false
	out := applyWindowsServiceHardening(nil, `C:\Program Files\EDR\edr.exe`, c)
	if out["applied"] != false {
		t.Fatalf("expected applied=false, got %#v", out)
	}
}
