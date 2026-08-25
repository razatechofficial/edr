package main

import "runtime"

const (
	productName    = "EDR Agent"
	productVersion = "1.0.0"
	apexSaaS       = "xdr.averox.com"
	eulaText       = "EDR Agent is installed for all users of this computer (per-machine). It cannot be installed for a single account: host monitoring must cover every session on the device.\n\nTelemetry is sent only to your organization’s XDR tenant. Stopping or removing the agent requires administrator credentials.\n\nBy choosing Accept you agree to the license terms. In enterprise fleets this screen is skipped: the organization accepts the license by deploying the package silently."
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
		return "Grant access in System Settings, then Recheck. The sensor cannot start until every item is green."
	case "windows":
		return "Allow EDR Agent through Windows Firewall if prompted, then Recheck."
	default:
		return "Linux has no grant wizard. Capabilities are checked at Start."
	}
}

func enrollBody() string {
	return "Paste the one-time token from the console. Leave domain blank to use " + apexSaaS +
		". The agent maps it to enroll." + apexSaaS + ". Ingest is returned by Register, not typed."
}

func domainCaption() string {
	return "Blank uses " + apexSaaS + ". Maps to enroll." + apexSaaS + ":443. Not ingest or API URLs."
}
