package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/hostperm"
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
	Doing  string
	Detail string
	State  checkState
}

func newPreflightItems() []preflightItem {
	items := []preflightItem{
		{ID: "cert", Title: "Device certificate valid", Doing: "Checking device identity certificate…"},
	}
	switch {
	case isDarwin():
		items = append(items, preflightItem{ID: "grants", Title: "OS permissions still granted", Doing: "Re-checking System Extension and Full Disk Access…"})
	case isWindows():
		items = append(items, preflightItem{ID: "grants", Title: "Firewall and service rights", Doing: "Re-checking Windows Firewall and service rights…"})
	default:
		items = append(items, preflightItem{ID: "grants", Title: "Kernel and audit capabilities", Doing: "Re-checking Linux capabilities…"})
	}
	svc := "Sensor service registered"
	if isWindows() {
		svc = "EDRAgent service registered"
	}
	items = append(items,
		preflightItem{ID: "svc", Title: svc, Doing: "Checking the machine-wide sensor service…"},
		preflightItem{ID: "spool", Title: "Local event spool writable", Doing: "Checking offline telemetry spool…"},
	)
	return items
}

func runOneCheck(id string, st operatorStatus) (ok bool, detail string) {
	switch id {
	case "cert":
		if !st.Enrolled && strings.TrimSpace(st.AgentID) == "" {
			return false, "This host is not enrolled. Return to Enroll with a new token."
		}
		if !st.Enrolled {
			return true, "Device identity from this session. Certificate is in the OS keystore."
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
		rep := hostperm.EvaluateQuick()
		if !hostperm.GrantsReady(rep) {
			id := ""
			detail := "Required OS access was revoked."
			for _, it := range hostperm.GrantItems(rep) {
				if it.Required && it.Status != hostperm.StatusOK && it.Status != hostperm.StatusNA {
					id = it.Title
					if it.Doing != "" {
						detail = it.Doing
					}
					break
				}
			}
			if id != "" {
				return false, id + " — " + detail
			}
			return false, detail
		}
		if isDarwin() {
			return true, "OS permissions are granted"
		}
		if isWindows() {
			return true, "Service rights look healthy"
		}
		return true, "Required capabilities are present"
	case "svc":
		s := strings.ToLower(strings.TrimSpace(st.Service))
		if s == "" || s == "unknown" || strings.Contains(s, "not installed") || strings.Contains(s, "missing") {
			return false, "The machine-wide sensor service is not registered. Reinstall as administrator."
		}
		if s == "not loaded" || s == "not running" || s == "stopped" {
			return true, "Service is installed. Start loads the sensor."
		}
		return true, "Service: " + st.Service
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
