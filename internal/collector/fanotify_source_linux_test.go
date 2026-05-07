//go:build linux

package collector

import (
	"testing"

	"golang.org/x/sys/unix"
)

func Test_readMountinfoFingerprint_nonEmpty(t *testing.T) {
	fp, err := readMountinfoFingerprint()
	if err != nil {
		t.Skip(err)
	}
	if len(fp) != 64 {
		t.Fatalf("expected sha256 hex len 64, got %d", len(fp))
	}
}

func TestFanotifySource_ExportMonitoringHealth_NotStarted(t *testing.T) {
	t.Parallel()
	f := NewFanotifySource("ep", "h", nil, []string{"/"}, nil)
	m := f.ExportMonitoringHealth()
	if m["status"] != "unavailable" {
		t.Fatalf("status: %v", m["status"])
	}
}

func TestFanotifySource_Start_FIDFallback(t *testing.T) {
	t.Parallel()
	oldInit := fanotifyInitFn
	defer func() { fanotifyInitFn = oldInit }()

	calls := 0
	fanotifyInitFn = func(flags uint, _ uint) (int, error) {
		calls++
		if flags&uint(unix.FAN_REPORT_FID) != 0 {
			return -1, unix.EINVAL
		}
		return -1, unix.EPERM // stop before marks; we only validate retry behavior
	}

	f := NewFanotifySource("ep", "h", nil, []string{"/"}, nil)
	f.fanReportFIDCap = true
	if err := f.Start(); err == nil {
		t.Fatal("expected init failure")
	}
	if calls < 2 {
		t.Fatalf("expected fallback retry without FID, calls=%d", calls)
	}
	if f.fanReportFIDEnabled {
		t.Fatal("expected fid enabled=false after fallback")
	}
}
