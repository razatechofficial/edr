package detection

import (
	"fmt"
	"strings"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// CredentialDetector identifies credential theft by detecting access to
// sensitive credential stores (lsass, SAM, NTDS.dit, /etc/shadow, Keychain,
// browser credential databases) and known credential dump tool execution.
type CredentialDetector struct {
	logger *zap.Logger
}

// NewCredentialDetector creates a CredentialDetector.
func NewCredentialDetector(logger *zap.Logger) *CredentialDetector {
	return &CredentialDetector{logger: logger}
}

// Name returns the detector identifier.
func (d *CredentialDetector) Name() string { return "credential" }

// Analyze evaluates file access and process execution events for credential
// theft indicators.
func (d *CredentialDetector) Analyze(event interface{}, correlator *Correlator) []*events.Alert {
	pid := extractPID(event)
	if pid == 0 {
		return nil
	}

	var alerts []*events.Alert
	if a := d.checkCredentialFiles(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkCredentialTools(event, pid); a != nil {
		alerts = append(alerts, a)
	}
	if a := d.checkBrowserCreds(event, pid); a != nil {
		alerts = append(alerts, a)
	}

	// Escalate severity when correlator shows multiple credential access patterns
	if len(alerts) > 0 {
		recent := correlator.GetProcessEvents(pid, Window5m)
		credCount := 0
		for _, ev := range recent {
			p := strings.ToLower(extractFilePath(ev))
			c := strings.ToLower(extractCommandLine(ev))
			if containsAny(p, credentialFilePatterns...) || containsAny(c, credentialToolPatterns...) {
				credCount++
			}
		}
		if credCount >= 3 {
			for _, a := range alerts {
				a.Severity = events.SeverityCritical
				a.Tags = append(a.Tags, "multi_credential_access", "action:host_isolate")
			}
		}
	}

	return alerts
}

// Reset is a no-op; the detector is stateless.
func (d *CredentialDetector) Reset() {}

// ---------------------------------------------------------------------------
// Sensitive credential file access
// ---------------------------------------------------------------------------

var credentialFilePatterns = []string{
	// Windows
	"\\system32\\config\\sam",
	"\\system32\\config\\security",
	"\\system32\\config\\system",
	"ntds.dit",
	"lsass.dmp",
	"lsass.exe",
	// Linux
	"/etc/shadow",
	"/etc/gshadow",
	// macOS
	"login.keychain",
	"login.keychain-db",
	"system.keychain",
	// SSH keys
	".ssh/id_rsa",
	".ssh/id_ed25519",
	".ssh/id_ecdsa",
	// GPG
	".gnupg/secring",
	".gnupg/private-keys",
}

func (d *CredentialDetector) checkCredentialFiles(event interface{}, pid uint32) *events.Alert {
	path := strings.ToLower(extractFilePath(event))
	if path == "" {
		return nil
	}

	for _, pattern := range credentialFilePatterns {
		if !strings.Contains(path, pattern) {
			continue
		}

		mitre := credentialFileMITRE(pattern)
		d.logger.Warn("credential file access",
			zap.Uint32("pid", pid), zap.String("path", path))
		return newAlert(
			"CRED-001", "credential", "Credential store access detected",
			fmt.Sprintf("PID %d accessed sensitive credential file: %s", pid, extractFilePath(event)),
			events.SeverityHigh,
			mitre,
			[]string{"credential_theft", "action:kill_process"}, event,
		)
	}
	return nil
}

func credentialFileMITRE(pattern string) []events.MITREAttack {
	switch {
	case containsAny(pattern, "lsass"):
		return []events.MITREAttack{{TechniqueID: "T1003.001", TechniqueName: "LSASS Memory", TacticID: "TA0006", TacticName: "Credential Access"}}
	case containsAny(pattern, "sam", "security"):
		return []events.MITREAttack{{TechniqueID: "T1003.002", TechniqueName: "Security Account Manager", TacticID: "TA0006", TacticName: "Credential Access"}}
	case containsAny(pattern, "ntds"):
		return []events.MITREAttack{{TechniqueID: "T1003.003", TechniqueName: "NTDS", TacticID: "TA0006", TacticName: "Credential Access"}}
	case containsAny(pattern, "/etc/shadow", "/etc/gshadow"):
		return []events.MITREAttack{{TechniqueID: "T1003.008", TechniqueName: "/etc/passwd and /etc/shadow", TacticID: "TA0006", TacticName: "Credential Access"}}
	case containsAny(pattern, "keychain"):
		return []events.MITREAttack{{TechniqueID: "T1555.001", TechniqueName: "Keychain", TacticID: "TA0006", TacticName: "Credential Access"}}
	case containsAny(pattern, ".ssh/"):
		return []events.MITREAttack{{TechniqueID: "T1552.004", TechniqueName: "Private Keys", TacticID: "TA0006", TacticName: "Credential Access"}}
	default:
		return []events.MITREAttack{{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", TacticID: "TA0006", TacticName: "Credential Access"}}
	}
}

// ---------------------------------------------------------------------------
// Known credential dump tools
// ---------------------------------------------------------------------------

var credentialToolPatterns = []string{
	"mimikatz", "sekurlsa", "secretsdump", "gsecdump",
	"hashdump", "pypykatz", "lazagne", "rubeus",
	"kerberoast", "ntdsutil", "vaultcmd", "cmdkey /list",
	"procdump -ma lsass", "procdump.exe -ma lsass",
	"security dump-keychain", "security find-generic-password",
}

func (d *CredentialDetector) checkCredentialTools(event interface{}, pid uint32) *events.Alert {
	cmd := strings.ToLower(extractCommandLine(event))
	proc := strings.ToLower(extractProcessName(event))
	if cmd == "" && proc == "" {
		return nil
	}

	if !containsAny(cmd, credentialToolPatterns...) && !containsAny(proc, "mimikatz", "secretsdump", "gsecdump", "pypykatz", "lazagne", "rubeus") {
		return nil
	}

	d.logger.Warn("credential dump tool detected",
		zap.Uint32("pid", pid), zap.String("process", extractProcessName(event)))
	return newAlert(
		"CRED-002", "credential", "Credential dump tool execution",
		fmt.Sprintf("PID %d executed credential dump tool: %s", pid, extractProcessName(event)),
		events.SeverityCritical,
		[]events.MITREAttack{
			{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", TacticID: "TA0006", TacticName: "Credential Access"},
		},
		[]string{"credential_theft", "action:kill_process", "action:host_isolate"}, event,
	)
}

// ---------------------------------------------------------------------------
// Browser credential database access
// ---------------------------------------------------------------------------

var browserCredFiles = []string{
	"login data",
	"logins.json",
	"cookies.sqlite",
	"web data",
	"signons.sqlite",
	"key3.db",
	"key4.db",
	"cert9.db",
}

func (d *CredentialDetector) checkBrowserCreds(event interface{}, pid uint32) *events.Alert {
	path := strings.ToLower(extractFilePath(event))
	if path == "" {
		return nil
	}

	op := strings.ToLower(extractFileOperation(event))
	if op != "" && op != "read" && op != "open" && op != "copy" {
		return nil
	}

	for _, f := range browserCredFiles {
		if strings.Contains(path, f) {
			d.logger.Info("browser credential access",
				zap.Uint32("pid", pid), zap.String("file", f))
			return newAlert(
				"CRED-003", "credential", "Browser credential database access",
				fmt.Sprintf("PID %d accessed browser credential store: %s", pid, extractFilePath(event)),
				events.SeverityMedium,
				[]events.MITREAttack{
					{TechniqueID: "T1555.003", TechniqueName: "Credentials from Web Browsers", TacticID: "TA0006", TacticName: "Credential Access"},
				},
				[]string{"credential_theft", "browser"}, event,
			)
		}
	}
	return nil
}
