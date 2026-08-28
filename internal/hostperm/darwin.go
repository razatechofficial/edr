//go:build darwin

package hostperm

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func sensorBinaryHint() string {
	if p := launchdSensorProgram(); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	for _, p := range []string{
		"/usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent",
		"/Library/Application Support/EDR/bin/edr-agent",
		"/usr/local/bin/edr-agent",
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return "/usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent"
}

func launchdSensorProgram() string {
	b, err := os.ReadFile("/Library/LaunchDaemons/com.razatech.edr-agent.plist")
	if err != nil {
		return ""
	}
	s := string(b)
	i := strings.Index(s, "<key>ProgramArguments</key>")
	if i < 0 {
		return ""
	}
	rest := s[i:]
	const open, close = "<string>", "</string>"
	a := strings.Index(rest, open)
	if a < 0 {
		return ""
	}
	rest = rest[a+len(open):]
	b2 := strings.Index(rest, close)
	if b2 < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:b2])
}

func catalog() []Item {
	return []Item{
		{
			ID:            IDSysExt,
			Title:         "System Extension",
			Doing:         "Waiting for System Extension approval…",
			SettingsLabel: "Open Privacy & Security",
			Guide:         "System Settings → Privacy & Security → allow edr to load a system extension. Then Recheck.",
			Required:      false,
		},
		{
			ID:            IDFDA,
			Title:         "Full Disk Access",
			Doing:         "Waiting for Full Disk Access…",
			SettingsLabel: "Open Full Disk Access",
			Guide:         fdaGuide(),
			Required:      true,
		},
		{
			ID:            IDNetExt,
			Title:         "Network filter",
			Doing:         "Waiting for the network filter permission…",
			SettingsLabel: "Open Privacy & Security",
			Guide:         "Allow the network content filter if macOS asks. Then Recheck.",
			Required:      false,
		},
		{
			ID:       IDBootStart,
			Title:    "Start at login (all users)",
			Doing:    "Checking LaunchDaemon boot persistence…",
			Guide:    "The sensor is a LaunchDaemon so it starts at boot for every account on this Mac. Reinstall as administrator if this is red.",
			Required: true,
		},
		{
			ID:       IDLoginUI,
			Title:    "Console at user login",
			Doing:    "Checking the all-users Login Item…",
			Guide:    "A LaunchAgent in /Library/LaunchAgents opens edr at login for every user. Reinstall if this is missing.",
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
	case IDFDA:
		return evaluateFDA(it)
	case IDSysExt:
		return evaluateSysExt(it)
	case IDNetExt:
		return evaluateNetExt(it)
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

func sensorRunning() bool {
	out, err := runOutput(0, "launchctl", "print", "system/com.razatech.edr-agent")
	if err != nil {
		return false
	}
	low := strings.ToLower(out)
	if strings.Contains(low, "state = running") {
		return true
	}
	// launchctl print nests "state = running" under the program; also accept pid.
	return strings.Contains(low, "pid =") && !strings.Contains(low, "pid = 0") && !strings.Contains(low, "not running")
}

func fdaGuide() string {
	return "System Settings → Privacy & Security → Full Disk Access → enable edr. Then Recheck."
}

func evaluateFDA(it Item) Item {
	it.Guide = fdaGuide()
	hint := sensorBinaryHint()
	if probeProductFDA() {
		return ok(it, "")
	}
	clients, _ := tccFDAClients()
	if sensorListedInTCC(clients, hint) {
		return ok(it, "")
	}
	if helper, ok := evaluateFDAViaHelper(); ok && helper.Status == StatusOK {
		helper.Guide = it.Guide
		helper.Detail = ""
		return helper
	}
	return action(it, "")
}

func evaluateSysExt(it Item) Item {
	out, err := runOutput(0, "/usr/sbin/systemextensionsctl", "list")
	if err != nil || strings.TrimSpace(out) == "" {
		return na(it, "This build uses Endpoint Security inside the sensor. macOS will only ask for a System Extension if one is shipped.")
	}
	low := strings.ToLower(out)
	if !strings.Contains(low, "razatech") && !strings.Contains(low, "edr") {
		return na(it, "No EDR system extension is installed. Endpoint Security runs in the sensor process.")
	}
	if strings.Contains(low, "activated enabled") || strings.Contains(low, "[activated enabled]") {
		return ok(it, "System extension is activated.")
	}
	if strings.Contains(low, "waiting for user") || strings.Contains(low, "terminated waiting") {
		return action(it, "Approve the EDR system extension in Privacy & Security, then Recheck.")
	}
	return action(it, "System extension is registered but not enabled.")
}

func evaluateNetExt(it Item) Item {
	out, err := runOutput(0, "/usr/sbin/systemextensionsctl", "list")
	if err != nil {
		return na(it, "No network content filter is registered for this build.")
	}
	low := strings.ToLower(out)
	if !strings.Contains(low, "network") && !strings.Contains(low, "content filter") {
		return na(it, "No network filter extension is installed. Allow it only if macOS prompts.")
	}
	if strings.Contains(low, "activated enabled") {
		return ok(it, "Network filter is allowed.")
	}
	return action(it, "Allow the network content filter if macOS asks, then Recheck.")
}

func evaluateBoot(it Item) Item {
	plist := "/Library/LaunchDaemons/com.razatech.edr-agent.plist"
	b, err := os.ReadFile(plist)
	if err != nil {
		return fail(it, "LaunchDaemon is not installed. Reinstall as administrator.")
	}
	s := string(b)
	if strings.Contains(s, "<key>RunAtLoad</key>") && strings.Contains(s, "<false/>") {
		if sensorRunning() {
			return ok(it, "Sensor is running. This package does not auto-start at boot (RunAtLoad is false); reinstall to fix.")
		}
		it.Required = false
		return action(it, "The sensor will not start at boot until this package is upgraded (RunAtLoad is false).")
	}
	return ok(it, "LaunchDaemon starts at boot for every user of this Mac.")
}

func evaluateLoginUI(it Item) Item {
	plist := "/Library/LaunchAgents/com.razatech.edr-agent-ui.plist"
	if _, err := os.Stat(plist); err != nil {
		return na(it, "")
	}
	uid := os.Getuid()
	label := fmt.Sprintf("gui/%d/com.razatech.edr-agent-ui", uid)
	out, err := runOutput(2*time.Second, "launchctl", "print", label)
	low := strings.ToLower(out)
	if err != nil || strings.Contains(low, "could not find") || strings.Contains(low, "service not found") {
		it.Guide = "System Settings → General → Login Items → enable edr, then Recheck."
		it.Doing = "Waiting for the login item…"
		return action(it, "")
	}
	return ok(it, "")
}

func evaluateService(it Item) Item {
	if _, err := os.Stat("/Library/LaunchDaemons/com.razatech.edr-agent.plist"); err != nil {
		return fail(it, "The machine-wide sensor service is not registered. Reinstall as administrator.")
	}
	if sensorRunning() {
		return ok(it, "Service: running")
	}
	return ok(it, "Service is installed. Start loads the sensor.")
}

// OpenSettings opens the System Settings pane for the catalog row.
func OpenSettings(id string) error {
	_ = exec.Command("/usr/bin/open", "-a", "System Settings").Start()
	time.Sleep(400 * time.Millisecond)
	var last error
	for _, u := range settingsURLs(id) {
		last = exec.Command("/usr/bin/open", u).Run()
		if last == nil {
			return nil
		}
	}
	last = exec.Command("/usr/bin/osascript", "-e", `tell application "System Settings" to activate`).Run()
	if last != nil {
		last = exec.Command("/usr/bin/open", "-b", "com.apple.systempreferences").Run()
	}
	return last
}

func settingsURLs(id string) []string {
	switch id {
	case IDFDA:
		return []string{
			"x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles",
			"x-apple.systempreferences:com.apple.settings.PrivacySecurity.Privacy_AllFiles",
			"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
			"x-apple.systempreferences:com.apple.preference.security?Privacy",
		}
	case IDSysExt, IDNetExt:
		return []string{
			"x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension",
			"x-apple.systempreferences:com.apple.preference.security?General",
		}
	case IDLoginUI, IDBootStart:
		return []string{
			"x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
			"x-apple.systempreferences:com.apple.settings.LoginItems",
		}
	default:
		return []string{
			"x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension",
			"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
		}
	}
}
