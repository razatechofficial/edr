package main

import (
	"runtime"
	"strings"
)

// Set by -X main.version=… in release builds (git describe).
var version = productVersion

const (
	productName    = "edr"
	productVersion = "1.0.0"
	apexSaaS       = "xdr.averox.com"
	eulaText       = "edr is installed for all users of this computer (per-machine). It cannot be installed for a single account: host monitoring must cover every session on the device.\n\nTelemetry is sent only to your organization’s XDR tenant. Stopping or removing the agent requires administrator credentials.\n\nBy choosing Accept you agree to the license terms. In enterprise fleets this screen is skipped: the organization accepts the license by deploying the package silently."

	kickerLicense   = "License agreement"
	titleLicense    = "Software license"
	bodyLicense     = "Read and accept to install. Silent fleet skips this screen — the organization accepts by deploying the package."
	perMachineTitle = "Installs for all users of this computer"
	perMachineBody  = "Required for host monitoring. This is not a “this user only” app."
	kickerSetup     = "Setup complete"
	titleInstalled  = "Files are installed"
	launchHint      = "Launch opens first-run enrollment. The sensor starts after identity and checks pass."
	progressKicker  = "Copy files"
	progressTitle   = "Installing edr"
	allChecksPassed = "All checks passed."

	tuiBodyLicense    = "Attended TUI. Silent rpm/deb skips this; the org accepts by deploying."
	tuiPerMachineBody = "Statement, not a choice. Per-machine systemd unit."
	tuiInstallKicker  = "copy files"
	tuiInstallTitle   = "Installing EDR Agent"
	tuiInstallHint    = "Machine-wide package + systemd unit. No token here."
	tuiFinishBody     = "Not enrolled yet. First-run is sudo edrctl enroll — same contract as Launch on Windows/macOS."
	tuiFooterInstall  = "Tab select   Enter confirm   q quit"
	tuiFooterWait     = "Wait for checks   Enter when ready"
	tuiFooterNext     = "Next: sudo edrctl enroll"
	tuiLaunchEnroll   = "Launch enroll"
)

func storageLabel() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS Keychain"
	case "windows":
		return "Windows DPAPI"
	default:
		return "Sealed local keystore"
	}
}

func openSettingsLabel() string {
	switch runtime.GOOS {
	case "darwin":
		return "Open System Settings"
	case "windows":
		return "Open Windows Security"
	default:
		return "See documentation"
	}
}

func permBody() string {
	switch runtime.GOOS {
	case "darwin":
		return "System Settings opens Full Disk Access. Enable the sensor binary (edr-agent), not only the dashboard. Then Recheck. The sensor cannot start until this is green."
	case "windows":
		return "Allow edr through Windows Firewall if prompted, then Recheck. Startup apps can be opened from this screen."
	default:
		return "Linux has no grant wizard. Capabilities are checked at Start."
	}
}

func enrollBody() string {
	return "Paste the one-time token from the console. Leave the management domain blank to use the default " + apexSaaS + "."
}

func domainCaption() string {
	return "Leave blank to use the default " + apexSaaS + "."
}

func installedBody() string { return installedBodyFor(hostKind()) }

func installedBodyFor(os string) string {
	switch os {
	case "macos":
		return "This Mac is not enrolled yet. Launch edr to bind device identity, then grant access in System Settings."
	case "windows":
		return "This PC is not enrolled yet. Launch edr to bind device identity, then allow the firewall if Windows asks."
	default:
		return "This host is not enrolled yet. Run sudo edrctl enroll to bind device identity."
	}
}

func installProgressHint() string { return installProgressHintFor(hostKind()) }

func installProgressHintFor(os string) string {
	switch os {
	case "macos":
		return "Copies files and registers the LaunchDaemon. No token on this screen."
	case "windows":
		return "Copies files to Program Files and registers the EDRAgent service. No token on this screen."
	default:
		return "Copies files and registers the machine-wide service. No token on this screen."
	}
}

func setupStepTitles() []string { return setupStepTitlesFor(hostKind()) }

func setupStepTitlesFor(os string) []string {
	switch os {
	case "macos":
		return []string{"macOS 12+ and disk space", "Install EDR Agent.app", "Register LaunchDaemon"}
	case "windows":
		return []string{"Windows 10+ and disk space", "Install to Program Files", "Register EDRAgent service"}
	default:
		return []string{"Kernel and disk space", "Install deb/rpm package", "Register systemd unit"}
	}
}

func packageVersion() string {
	v := strings.TrimSpace(version)
	if v == "" {
		return productVersion
	}
	return v
}

func setupStepDoing(i int) string { return setupStepDoingFor(hostKind(), i) }

func setupStepDoingFor(os string, i int) string {
	var d []string
	switch os {
	case "macos":
		d = []string{
			"Checking macOS 12+ and available disk space…",
			"Installing EDR Agent.app for all users…",
			"Registering the sensor LaunchDaemon…",
		}
	case "windows":
		d = []string{
			"Checking Windows 10+ and available disk space…",
			"Copying files to Program Files\\EDR Agent (all users)…",
			"Registering the per-machine EDRAgent service…",
		}
	default:
		d = []string{
			"Checking Linux kernel and available disk space…",
			"Installing the machine-wide agent package…",
			"Registering the systemd unit…",
		}
	}
	if i >= 0 && i < len(d) {
		return d[i]
	}
	return "Working…"
}
