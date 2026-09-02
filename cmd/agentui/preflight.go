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
		return serviceCheck(st)
	case "spool":
		return storageCheck()
	default:
		return false, "unknown check"
	}
}

func serviceLooksMissing(s string) bool {
	v := strings.ToLower(strings.TrimSpace(s))
	return v == "" || v == "unknown" || strings.Contains(v, "not installed") || strings.Contains(v, "missing")
}

func serviceCheck(st operatorStatus) (bool, string) {
	s := strings.ToLower(strings.TrimSpace(st.Service))
	if hostperm.SensorRegistered() {
		if s == "running" || s == "starting" || s == "start_pending" {
			return true, "Service: " + firstNonEmpty(st.Service, "running")
		}
		return true, "Service is installed. Start loads the sensor."
	}
	if serviceLooksMissing(st.Service) {
		return false, "The machine-wide sensor service is not registered. Reinstall as administrator."
	}
	if s == "not loaded" || s == "not running" || s == "stopped" || s == "installed" {
		return true, "Service is installed. Start loads the sensor."
	}
	return true, "Service: " + st.Service
}

func preflightCanStart(items []preflightItem) bool {
	svcFail := false
	for _, it := range items {
		if it.State == checkOK {
			continue
		}
		if it.ID == "svc" && it.State == checkFail {
			svcFail = true
			continue
		}
		return false
	}
	return len(items) > 0 || svcFail
}

func waitForService(d time.Duration) operatorStatus {
	deadline := time.Now().Add(d)
	var st operatorStatus
	for {
		st = loadStatus()
		if serviceHealthy(st.Service) {
			return st
		}
		if time.Now().After(deadline) {
			return st
		}
		time.Sleep(400 * time.Millisecond)
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
