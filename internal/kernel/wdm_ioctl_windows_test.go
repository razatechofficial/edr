//go:build windows

package kernel

import "testing"

func TestWDMIOCTLConstants(t *testing.T) {
	if IOCTL_EDRAddProtectedPID != 0x00222000 {
		t.Fatalf("IOCTL_EDRAddProtectedPID = 0x%x want 0x00222000", IOCTL_EDRAddProtectedPID)
	}
	if IOCTL_EDRGetStatus != 0x0022200c {
		t.Fatalf("IOCTL_EDRGetStatus = 0x%x want 0x0022200c", IOCTL_EDRGetStatus)
	}
}
