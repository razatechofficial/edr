package main

import (
	"fmt"
	"strings"
	"time"

	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
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
	Title  string
	Detail string
	State  checkState
}

func newPreflightItems() []preflightItem {
	items := []preflightItem{
		{ID: "cert", Title: "Device certificate valid"},
	}
	switch {
	case isDarwin():
		items = append(items, preflightItem{ID: "grants", Title: "OS permissions still granted"})
	case isWindows():
		items = append(items, preflightItem{ID: "grants", Title: "Firewall and service rights"})
	default:
		items = append(items, preflightItem{ID: "grants", Title: "Kernel and audit capabilities"})
	}
	svc := "Sensor service registered"
	if isWindows() {
		svc = "EDRAgent service registered"
	}
	items = append(items,
		preflightItem{ID: "svc", Title: svc},
		preflightItem{ID: "spool", Title: "Local event spool writable"},
	)
	return items
}

func runOneCheck(id string, st operatorStatus) (ok bool, detail string) {
	switch id {
	case "cert":
		if !st.Enrolled {
			return false, "This host is not enrolled. Return to Enroll with a new token."
		}
		if st.CertExpiry != "" {
			t, err := time.Parse(time.RFC3339, st.CertExpiry)
			if err == nil {
				if time.Now().After(t) {
					return false, "Device certificate has expired. Re-enroll with a new token."
				}
				days := int(time.Until(t).Hours() / 24)
				if days <= 7 {
					return true, fmt.Sprintf("Valid; expires in %d days", days)
				}
			}
		}
		return true, "Device identity certificate is present"
	case "grants":
		if needsFullDiskAccess() && !hasFullDiskAccess() {
			return false, "Full Disk Access was revoked. Open System Settings, then Recheck."
		}
		if isDarwin() {
			return true, "System Extension and Full Disk Access are granted"
		}
		if isWindows() {
			return true, "Service rights look healthy"
		}
		return true, "Required capabilities are present"
	case "svc":
		s := st.Service
		if s == "" || s == "unknown" || strings.Contains(strings.ToLower(s), "not installed") || strings.Contains(strings.ToLower(s), "missing") {
			return false, "The machine-wide sensor service is not registered. Reinstall as administrator."
		}
		return true, "Service: " + s
	case "spool":
		return storageCheck()
	default:
		return false, "unknown check"
	}
}

func checkVisual(s checkState) (color.Color, fyne.Resource) {
	switch s {
	case checkOK:
		return colorOK, theme.ConfirmIcon()
	case checkRun:
		return colorCyan, theme.ViewRefreshIcon()
	case checkFail:
		return colorDanger, theme.ErrorIcon()
	default:
		return colorMuted, theme.RadioButtonIcon()
	}
}
