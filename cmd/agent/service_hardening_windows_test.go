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

func TestApplyWindowsServiceHardening_NilServiceIncludesDACLField(t *testing.T) {
	t.Parallel()
	c := config.Defaults()
	c.Monitoring.WindowsServiceHardening = true
	c.Monitoring.WindowsServiceDaclHardened = true
	out := applyWindowsServiceHardening(nil, `C:\Program Files\EDR\edr.exe`, c)
	v, ok := out["service_dacl_hardened"].(bool)
	if !ok || v {
		t.Fatalf("expected service_dacl_hardened=false in nil-service posture, got %#v", out["service_dacl_hardened"])
	}
}
