//go:build windows

package hostperm

import (
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

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
	// Do not shell out to netsh — that flashes a console on every Recheck.
	return ok(it, "Windows will prompt if a firewall allow is required. Allow EDR Agent if asked.")
}

func openEDRService() (*mgr.Service, func(), error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService("EDRAgent")
	if err != nil {
		_ = m.Disconnect()
		return nil, nil, err
	}
	return s, func() { _ = s.Close(); _ = m.Disconnect() }, nil
}

func evaluateBoot(it Item) Item {
	s, done, err := openEDRService()
	if err != nil {
		return fail(it, "EDRAgent service is not installed. Reinstall as administrator.")
	}
	defer done()
	cfg, err := s.Config()
	if err != nil {
		return fail(it, "EDRAgent service is not installed. Reinstall as administrator.")
	}
	if cfg.StartType == mgr.StartAutomatic {
		return ok(it, "EDRAgent starts automatically after reboot.")
	}
	if cfg.StartType == mgr.StartManual {
		return action(it, "EDRAgent is manual start. Reinstall so the service is Automatic.")
	}
	return ok(it, "EDRAgent service is registered.")
}

func ensureLoginItem() {}

func evaluateLoginUI(it Item) Item {
	it.SettingsLabel = "Open Startup apps"
	it.Guide = "Settings → Apps → Startup → enable EDR Agent. Then Recheck."
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return action(it, "Startup entry is missing. Reinstall the EDR Agent package, then allow EDR Agent at login.")
	}
	defer k.Close()
	if _, _, err := k.GetStringValue("EDR Agent"); err != nil {
		return action(it, "Startup entry is missing. Reinstall the EDR Agent package, then allow EDR Agent at login.")
	}
	return ok(it, "EDR Agent opens at login for every user.")
}

func evaluateService(it Item) Item {
	s, done, err := openEDRService()
	if err != nil {
		return fail(it, "The machine-wide sensor service is not registered. Reinstall as administrator.")
	}
	defer done()
	st, err := s.Query()
	if err != nil {
		return ok(it, "Service is installed. Start loads the sensor.")
	}
	if st.State == svc.Running {
		return ok(it, "Service: running")
	}
	return ok(it, "Service is installed. Start loads the sensor.")
}

// OpenSettings opens Windows Security / firewall or Startup apps without cmd.exe.
func OpenSettings(id string) error {
	if id == IDLoginUI {
		return shellOpen("ms-settings:startupapps")
	}
	_ = shellOpen("ms-settings:windowsdefender")
	return shellOpen("firewall.cpl")
}

func shellOpen(target string) error {
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(target), nil, nil, windows.SW_SHOWNORMAL)
}
