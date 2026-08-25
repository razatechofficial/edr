package main

import (
	"strings"
)

type uiFault struct {
	Title  string
	Body   string
	Detail string
	Action string
}

func faultTokenMissing() uiFault {
	return uiFault{
		Title:  "Enrollment token is required",
		Body:   "Paste the one-time token from the console. It is not a password for your user account.",
		Detail: "Ask your admin for a new token if you do not have one.",
		Action: "OK",
	}
}

func faultDomainInvalid() uiFault {
	return uiFault{
		Title:  "Enter a hostname, not a URL list",
		Body:   "Use one domain such as xdr.averox.com or xdr.company.com. The agent adds enroll. itself.",
		Detail: "Do not paste https://, ports, or ingest hosts.",
		Action: "OK",
	}
}

func classifyEnrollError(raw string) uiFault {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case s == "":
		return uiFault{
			Title:  "Enrollment was rejected",
			Body:   "The enrollment service did not issue a device certificate. The private key never left this computer.",
			Detail: "Typical causes: token, tenant mismatch, or this device is already enrolled. See your admin.",
			Action: "Try again",
		}
	case strings.Contains(s, "expired"):
		return uiFault{
			Title:  "This token has expired",
			Body:   "One-time enrollment tokens are short-lived.",
			Detail: "Create a new token in the console and paste it here.",
			Action: "Try again",
		}
	case strings.Contains(s, "invalid") || strings.Contains(s, "unauth") || (strings.Contains(s, "permission denied") && strings.Contains(s, "token")):
		return uiFault{
			Title:  "This token was not accepted",
			Body:   "It may be mistyped, already used, or issued for another tenant.",
			Detail: "Request a new enrollment token from the console. Do not reuse a spent token.",
			Action: "Try again",
		}
	case strings.Contains(s, "rejected"):
		return uiFault{
			Title:  "Enrollment was rejected",
			Body:   "The enrollment service did not issue a device certificate. The private key never left this computer.",
			Detail: "Typical causes: token, tenant mismatch, or this device is already enrolled. See your admin.",
			Action: "Try again",
		}
	case strings.Contains(s, "dial") || strings.Contains(s, "unreachable") || strings.Contains(s, "no such host") ||
		strings.Contains(s, "connection refused") || strings.Contains(s, "i/o timeout") || strings.Contains(s, "timeout"):
		return uiFault{
			Title:  "Can’t reach the enrollment service",
			Body:   "This computer could not open a secure connection. The sensor is not enrolled yet.",
			Detail: networkDetail(),
			Action: "Try again",
		}
	case strings.Contains(s, "keychain") || strings.Contains(s, "dpapi") || strings.Contains(s, "keystore") || strings.Contains(s, "store"):
		return uiFault{
			Title:  "Could not store the device certificate",
			Body:   "Enrollment reached the server, but this computer could not save the identity.",
			Detail: keystoreDetail(),
			Action: "Try again",
		}
	case strings.Contains(s, "administrator") || strings.Contains(s, "elevat") || strings.Contains(s, "permission denied") || strings.Contains(s, "sudo"):
		return uiFault{
			Title:  "Administrator rights required",
			Body:   "EDR Agent installs for every account on this computer.",
			Detail: adminDetail(),
			Action: "OK",
		}
	default:
		f := uiFault{
			Title:  "Enrollment was rejected",
			Body:   "The enrollment service did not issue a device certificate. The private key never left this computer.",
			Detail: clipErr(raw),
			Action: "Try again",
		}
		if f.Detail == "" {
			f.Detail = "See your admin if this keeps happening."
		}
		return f
	}
}

func classifyInstallError(raw string) uiFault {
	s := strings.ToLower(raw)
	if strings.Contains(s, "agent binary not found") || (strings.Contains(s, "not found") && strings.Contains(s, "edr-agent")) {
		return uiFault{
			Title:  "Setup could not find the agent files",
			Body:   "Put edr-installer in the same folder as edr-agent and edrctl, then Accept again.",
			Detail: adminDetail(),
			Action: "Try again",
		}
	}
	if strings.Contains(s, "disk") || strings.Contains(s, "no space") {
		return uiFault{
			Title:  "Not enough disk space",
			Body:   "Setup cannot copy files until more space is free.",
			Detail: "Free space on the system volume, then run setup again.",
			Action: "OK",
		}
	}
	if strings.Contains(s, "administrator") || strings.Contains(s, "root privileges") || strings.Contains(s, "elevat") {
		return uiFault{
			Title:  "Administrator rights required",
			Body:   "EDR Agent installs for every account on this computer.",
			Detail: adminDetail(),
			Action: "OK",
		}
	}
	return classifyStartError(raw)
}

func classifyStartError(raw string) uiFault {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "spool") || strings.Contains(s, "no space") || strings.Contains(s, "disk"):
		return uiFault{
			Title:  "Offline event spool is not writable",
			Body:   "The sensor needs a local queue for when ingest is down. Start is blocked until this is fixed.",
			Detail: spoolDetail(),
			Action: "Try again",
		}
	case strings.Contains(s, "cert") && (strings.Contains(s, "expir") || strings.Contains(s, "valid")):
		return uiFault{
			Title:  "Device certificate is not valid",
			Body:   "This host cannot prove its identity to ingest until the certificate is renewed.",
			Detail: "Keep the device online so renewal can run, or re-enroll with a new token if your admin requires it.",
			Action: "OK",
		}
	default:
		return uiFault{
			Title:  "Could not register the sensor service",
			Body:   "Files may be on disk, but the machine-wide service did not start.",
			Detail: firstLine(raw),
			Action: "Try again",
		}
	}
}

func networkDetail() string {
	switch {
	case isDarwin():
		return "Check network and any proxy. If a firewall prompt appeared, allow EDR Agent."
	case isWindows():
		return "Check network and Windows Firewall. Allow EDR Agent if prompted."
	default:
		return "Check network, DNS, and that this host can reach enroll.<domain>:443."
	}
}

func keystoreDetail() string {
	switch {
	case isDarwin():
		return "Keychain did not accept the certificate. Unlock login keychain and retry Enroll."
	case isWindows():
		return "DPAPI / certificate store failed. Confirm you are an administrator and retry."
	default:
		return "The sealed keystore could not be written. Check permissions on the agent data directory."
	}
}

func adminDetail() string {
	switch {
	case isDarwin():
		return "Quit and reopen EDR Agent. Enter an administrator password when macOS asks."
	case isWindows():
		return "Right-click and choose Run as administrator, or deploy via MDM/GPO."
	default:
		return "Re-run with sudo. A non-root install cannot register systemd."
	}
}

func spoolDetail() string {
	if isLinux() {
		return "Check disk space and permissions on the agent data directory."
	}
	return "Check disk space and that EDR Agent may write to its program data folder."
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "Retry Start, or reinstall with an administrator account."
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return clipErr(s)
}
