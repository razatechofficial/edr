package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/xdrclient"
)

type checkState int

const (
	checkWait checkState = iota
	checkRun
	checkOK
	checkFail
)

type preflightItem struct {
	ID     string
	Code   string
	Title  string
	Detail string
	State  checkState
}

func (s checkState) Label() string {
	switch s {
	case checkOK:
		return "OK"
	case checkRun:
		return "CHKG"
	case checkFail:
		return "FAIL"
	default:
		return "WAIT"
	}
}

func probeTCP(host string, timeout time.Duration) error {
	h := strings.TrimSpace(host)
	if h == "" {
		h = xdrclient.DefaultEnrollmentHost
	}
	if _, _, err := net.SplitHostPort(h); err != nil {
		h = net.JoinHostPort(h, "443")
	}
	c, err := net.DialTimeout("tcp", h, timeout)
	if err != nil {
		return err
	}
	return c.Close()
}

func adminCheck() (ok bool, detail string) {
	switch runtime.GOOS {
	case "windows":
		if processIsAdmin() {
			return true, "Administrator token present"
		}
		return false, "Start EDR Agent from an elevated session"
	case "darwin":
		return true, "macOS will prompt for administrator to start the sensor"
	default:
		if os.Geteuid() == 0 {
			return true, "Running as root"
		}
		if _, err := exec.LookPath("pkexec"); err == nil {
			return true, "PolicyKit will prompt for administrator"
		}
		return false, "Administrator privileges are required"
	}
}

func networkCheck(host string) (ok bool, detail string) {
	h := strings.TrimSpace(host)
	if h == "" {
		h = xdrclient.DefaultEnrollmentHost
	}
	if err := probeTCP(h, 3*time.Second); err != nil {
		return false, fmt.Sprintf("%s unreachable (%v)", h, err)
	}
	ingest := xdrclient.DefaultIngestHost
	if err := probeTCP(ingest, 3*time.Second); err != nil {
		return true, fmt.Sprintf("Enrollment reachable; ingest %s still blocked", ingest)
	}
	return true, "Enrollment and ingest hosts reachable"
}

func newPreflightItems() []preflightItem {
	items := []preflightItem{
		{ID: "net", Code: "SYS.NET_CONN", Title: "Network connectivity"},
		{ID: "admin", Code: "SYS.ADMIN_PRV", Title: "Administrative access"},
	}
	if needsFullDiskAccess() {
		items = append(items, preflightItem{
			ID:    "fda",
			Code:  "SYS.FDA",
			Title: "Full Disk Access",
		})
	}
	items = append(items, preflightItem{
		ID:    "disk",
		Code:  "SYS.DSK_SPC",
		Title: "Storage space (2 GB required)",
	})
	return items
}

func runOneCheck(id, host string) (ok bool, detail string) {
	switch id {
	case "net":
		return networkCheck(host)
	case "admin":
		return adminCheck()
	case "fda":
		if hasFullDiskAccess() {
			return true, "Full Disk Access is granted"
		}
		return false, "Enable EDR Agent Sensor in System Settings → Privacy & Security → Full Disk Access"
	case "disk":
		return storageCheck()
	default:
		return false, "unknown check"
	}
}
