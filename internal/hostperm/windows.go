//go:build windows

package hostperm

import (
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/razatechofficial/edr/internal/platform"
)

func sensorBinaryHint() string {
	return filepath.Join(platform.InstallDir(), "edr-agent.exe")
}

func catalog() []Item {
	return []Item{
		{
			ID:            IDFirewall,
			Title:         "Windows Firewall",
			Doing:         "Waiting for the firewall allow prompt…",
			SettingsLabel: "Open Windows Security",
			Guide:         "Allow EDR Agent through Windows Defender Firewall if prompted. Then Recheck.",
			Required:      true,
		},
		{
			ID:       IDBootStart,
			Title:    "Start at boot (all users)",
			Doing:    "Checking the EDRAgent service start type…",
			Guide:    "EDRAgent must be a per-machine Automatic service so it starts after reboot for every user.",
			Required: true,
		},
		{
			ID:            IDLoginUI,
			Title:         "Console at user login",
			Doing:         "Checking the all-users startup entry…",
			SettingsLabel: "Open Startup apps",
			Guide:         "Settings → Apps → Startup → enable EDR Agent. Then Recheck.",
			Required:      false,
		},
		{
			ID:       IDService,
			Title:    "EDRAgent service registered",
			Doing:    "Checking the machine-wide sensor service…",
			Required: true,
		},
		{
			ID:       IDSpool,
			Title:    "Offline event spool",
			Doing:    "Checking 2–4 GiB reserved for ingest outages…",
			Required: true,
		},
	}
}

func evaluateItem(it Item) Item {
	switch it.ID {
	case IDFirewall:
		return evaluateFirewall(it)
	case IDBootStart:
		return evaluateBoot(it)
	case IDLoginUI:
		return evaluateLoginUI(it)
	case IDService:
		return evaluateService(it)
	case IDSpool:
		return evaluateSpool(it)
	default:
		return na(it, "unknown check")
	}
}

func evaluateFirewall(it Item) Item {
	out, err := runOutput(0, "netsh", "advfirewall", "firewall", "show", "rule", "name=EDR Agent")
	if err == nil && containsFold(out, "enabled") {
		return ok(it, "Firewall rule EDR Agent is present.")
	}
	// No rule yet is normal until first outbound connect; do not block Start.
	return ok(it, "Windows will prompt if a firewall allow is required. Allow EDR Agent if asked.")
}

func scQuery() string {
	out, _ := runOutput(0, "sc", "query", "EDRAgent")
	return out
}

func scQC() string {
	out, _ := runOutput(0, "sc", "qc", "EDRAgent")
	return out
}

func evaluateBoot(it Item) Item {
	qc := scQC()
	if qc == "" || containsFold(qc, "does not exist") || containsFold(qc, "1060") {
		return fail(it, "EDRAgent service is not installed. Reinstall as administrator.")
	}
	if containsFold(qc, "auto_start") || containsFold(qc, "automatic") {
		return ok(it, "EDRAgent starts automatically after reboot.")
	}
	if containsFold(qc, "demand_start") {
		return action(it, "EDRAgent is manual start. Reinstall so the service is Automatic.")
	}
	return ok(it, "EDRAgent service is registered.")
}

func ensureLoginItem() {}

func evaluateLoginUI(it Item) Item {
	it.SettingsLabel = "Open Startup apps"
	it.Guide = "Settings → Apps → Startup → enable EDR Agent. Then Recheck."
	out, err := runOutput(0, "reg", "query", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, "/v", "EDR Agent")
	if err != nil || strings.TrimSpace(out) == "" {
		return action(it, "Startup entry is missing. Reinstall from Setup, then allow EDR Agent at login.")
	}
	return ok(it, "EDR Agent opens at login for every user.")
}

func evaluateService(it Item) Item {
	q := scQuery()
	if q == "" || containsFold(q, "does not exist") || containsFold(q, "1060") {
		return fail(it, "The machine-wide sensor service is not registered. Reinstall as administrator.")
	}
	if containsFold(q, "running") {
		return ok(it, "Service: running")
	}
	return ok(it, "Service is installed. Start loads the sensor.")
}

// OpenSettings opens Windows Security / firewall or Startup apps.
func OpenSettings(id string) error {
	if id == IDLoginUI {
		return exec.Command("cmd", "/c", "start", "", "ms-settings:startupapps").Start()
	}
	_ = exec.Command("cmd", "/c", "start", "", "windowsdefender:").Start()
	_ = exec.Command("cmd", "/c", "start", "", "ms-settings:windowsdefender").Start()
	return exec.Command("control", "firewall.cpl").Start()
}
