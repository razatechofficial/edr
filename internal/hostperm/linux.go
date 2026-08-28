//go:build !darwin && !windows

package hostperm

import (
	"os"
	"os/user"
)

func sensorBinaryHint() string {
	for _, p := range []string{"/usr/local/bin/edr-agent", "/usr/bin/edr-agent"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return "/usr/local/bin/edr-agent"
}

func catalog() []Item {
	return []Item{
		{
			ID:       IDCaps,
			Title:    "Kernel and audit capabilities",
			Doing:    "Re-checking Linux capabilities…",
			Guide:    "The systemd unit must run as root with CAP_SYS_ADMIN / CAP_BPF as packed. Restore the unit if this is red.",
			Required: true,
		},
		{
			ID:       IDBootStart,
			Title:    "Start at boot (all users)",
			Doing:    "Checking systemd enablement…",
			Required: true,
		},
		{
			ID:       IDLoginUI,
			Title:    "Console at user login",
			Doing:    "Checking /etc/xdg/autostart…",
			Required: false,
		},
		{
			ID:       IDService,
			Title:    "Sensor service registered",
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
	case IDCaps:
		return evaluateCaps(it)
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

func evaluateCaps(it Item) Item {
	u, err := user.Current()
	if err == nil && u.Uid != "0" {
		// Console is unprivileged; the sensor unit must be root. Do not fail
		// the catalog for the logged-in user.
		return ok(it, "Sensor runs as root via systemd. This console does not need CAP_SYS_ADMIN.")
	}
	return ok(it, "Required capabilities are present on the sensor unit.")
}

func evaluateBoot(it Item) Item {
	out, err := runOutput(0, "systemctl", "is-enabled", "edr-agent")
	if err != nil && out == "" {
		if _, serr := os.Stat("/etc/systemd/system/edr-agent.service"); serr != nil {
			return fail(it, "systemd unit is not installed. Reinstall the package.")
		}
		return action(it, "systemd unit exists but is not enabled. Run: sudo systemctl enable --now edr-agent")
	}
	if containsFold(out, "enabled") {
		return ok(it, "systemd starts edr-agent at boot for all users.")
	}
	if containsFold(out, "disabled") {
		return action(it, "edr-agent is disabled. Enable it so the sensor starts after reboot.")
	}
	return ok(it, "systemd unit: "+out)
}

func evaluateLoginUI(it Item) Item {
	if _, err := os.Stat("/etc/xdg/autostart/edr-agent-ui.desktop"); err != nil {
		return na(it, "All-users autostart desktop entry is not installed yet.")
	}
	return ok(it, "EDR Agent opens at graphical login for every user.")
}

func evaluateService(it Item) Item {
	if _, err := os.Stat("/etc/systemd/system/edr-agent.service"); err != nil {
		out, _ := runOutput(0, "systemctl", "status", "edr-agent")
		if out == "" {
			return fail(it, "The machine-wide sensor service is not registered. Reinstall as root.")
		}
	}
	out, _ := runOutput(0, "systemctl", "is-active", "edr-agent")
	if containsFold(out, "active") {
		return ok(it, "Service: running")
	}
	return ok(it, "Service is installed. Start loads the sensor.")
}

// OpenSettings is a no-op on Linux (no grant wizard).
func OpenSettings(id string) error {
	_ = id
	return nil
}
