package rules

import (
	"regexp"
	"sort"
	"strings"

	"github.com/razatechofficial/edr/pkg/events"
)

// reSigmaTechniqueTag matches the technique half of a Sigma attack tag:
// "t1059" or "t1059.001", which is what every rule in rules/sigma carries.
//
// It exists so a technique the curated table has never heard of still comes
// back with its ID. The table is a convenience for names and tactics, not the
// authority on which techniques exist — ATT&CK adds techniques faster than any
// hand-maintained Go slice is updated, and a rule that fires with no technique
// ID is a rule the console cannot attribute, the validation suite cannot match
// (it compares on TechniqueID) and an analyst cannot pivot from.
var reSigmaTechniqueTag = regexp.MustCompile(`^t([0-9]{4})(\.([0-9]{3}))?$`)

// canonicalTechniqueID converts a Sigma tag body to an ATT&CK technique ID,
// reporting whether it is a well-formed one.
func canonicalTechniqueID(value string) (string, bool) {
	if !reSigmaTechniqueTag.MatchString(value) {
		return "", false
	}
	return strings.ToUpper(value), true
}

// Technique represents a MITRE ATT&CK technique.
type Technique struct {
	ID          string
	Name        string
	TacticID    string
	TacticName  string
	Description string
	Platforms   []string
}

// MITREMapper maps detection rule IDs and tags to MITRE ATT&CK techniques.
type MITREMapper struct {
	techniques map[string]*Technique
	tactics    map[string]string // tactic ID -> display name
	tagMap     map[string]string // sigma tag suffix -> technique or tactic ID
}

// NewMITREMapper initializes a mapper pre-loaded with the most common ATT&CK techniques.
func NewMITREMapper() *MITREMapper {
	m := &MITREMapper{
		techniques: make(map[string]*Technique, 128),
		tactics:    make(map[string]string, 16),
		tagMap:     make(map[string]string, 128),
	}
	m.initTactics()
	m.initTechniques()
	return m
}

func (m *MITREMapper) initTactics() {
	tacticDefs := []struct {
		id, name, tag string
	}{
		{"TA0001", "Initial Access", "initial_access"},
		{"TA0002", "Execution", "execution"},
		{"TA0003", "Persistence", "persistence"},
		{"TA0004", "Privilege Escalation", "privilege_escalation"},
		{"TA0005", "Defense Evasion", "defense_evasion"},
		{"TA0006", "Credential Access", "credential_access"},
		{"TA0007", "Discovery", "discovery"},
		{"TA0008", "Lateral Movement", "lateral_movement"},
		{"TA0009", "Collection", "collection"},
		{"TA0010", "Exfiltration", "exfiltration"},
		{"TA0011", "Command and Control", "command_and_control"},
		{"TA0040", "Impact", "impact"},
		{"TA0042", "Resource Development", "resource_development"},
		{"TA0043", "Reconnaissance", "reconnaissance"},
	}
	for _, t := range tacticDefs {
		m.tactics[t.id] = t.name
		m.tagMap[t.tag] = t.id
	}
}

func (m *MITREMapper) initTechniques() {
	allPlatforms := []string{"linux", "macos", "windows"}
	winLinux := []string{"linux", "windows"}
	winOnly := []string{"windows"}
	linMac := []string{"linux", "macos"}
	macOnly := []string{"macos"}
	linuxOnly := []string{"linux"}

	defs := []Technique{
		// TA0001 - Initial Access
		{ID: "T1190", Name: "Exploit Public-Facing Application", TacticID: "TA0001", TacticName: "Initial Access", Platforms: allPlatforms},
		{ID: "T1133", Name: "External Remote Services", TacticID: "TA0001", TacticName: "Initial Access", Platforms: allPlatforms},
		{ID: "T1566", Name: "Phishing", TacticID: "TA0001", TacticName: "Initial Access", Platforms: allPlatforms},
		{ID: "T1566.001", Name: "Spearphishing Attachment", TacticID: "TA0001", TacticName: "Initial Access", Platforms: allPlatforms},
		{ID: "T1566.002", Name: "Spearphishing Link", TacticID: "TA0001", TacticName: "Initial Access", Platforms: allPlatforms},
		{ID: "T1078", Name: "Valid Accounts", TacticID: "TA0001", TacticName: "Initial Access", Platforms: allPlatforms},
		{ID: "T1195", Name: "Supply Chain Compromise", TacticID: "TA0001", TacticName: "Initial Access", Platforms: allPlatforms},
		{ID: "T1199", Name: "Trusted Relationship", TacticID: "TA0001", TacticName: "Initial Access", Platforms: allPlatforms},

		// TA0002 - Execution
		{ID: "T1059", Name: "Command and Scripting Interpreter", TacticID: "TA0002", TacticName: "Execution", Platforms: allPlatforms},
		{ID: "T1059.001", Name: "PowerShell", TacticID: "TA0002", TacticName: "Execution", Platforms: winOnly},
		{ID: "T1059.002", Name: "AppleScript", TacticID: "TA0002", TacticName: "Execution", Platforms: []string{"macos"}},
		{ID: "T1059.003", Name: "Windows Command Shell", TacticID: "TA0002", TacticName: "Execution", Platforms: winOnly},
		{ID: "T1059.004", Name: "Unix Shell", TacticID: "TA0002", TacticName: "Execution", Platforms: linMac},
		{ID: "T1059.005", Name: "Visual Basic", TacticID: "TA0002", TacticName: "Execution", Platforms: winOnly},
		{ID: "T1059.006", Name: "Python", TacticID: "TA0002", TacticName: "Execution", Platforms: allPlatforms},
		{ID: "T1059.007", Name: "JavaScript", TacticID: "TA0002", TacticName: "Execution", Platforms: allPlatforms},
		{ID: "T1106", Name: "Native API", TacticID: "TA0002", TacticName: "Execution", Platforms: allPlatforms},
		{ID: "T1053", Name: "Scheduled Task/Job", TacticID: "TA0002", TacticName: "Execution", Platforms: allPlatforms},
		{ID: "T1053.003", Name: "Cron", TacticID: "TA0002", TacticName: "Execution", Platforms: linMac},
		{ID: "T1053.005", Name: "Scheduled Task", TacticID: "TA0002", TacticName: "Execution", Platforms: winOnly},
		{ID: "T1204", Name: "User Execution", TacticID: "TA0002", TacticName: "Execution", Platforms: allPlatforms},
		{ID: "T1047", Name: "Windows Management Instrumentation", TacticID: "TA0002", TacticName: "Execution", Platforms: winOnly},
		{ID: "T1569", Name: "System Services", TacticID: "TA0002", TacticName: "Execution", Platforms: allPlatforms},
		{ID: "T1569.002", Name: "Service Execution", TacticID: "TA0002", TacticName: "Execution", Platforms: winOnly},

		// TA0003 - Persistence
		{ID: "T1547", Name: "Boot or Logon Autostart Execution", TacticID: "TA0003", TacticName: "Persistence", Platforms: allPlatforms},
		{ID: "T1547.001", Name: "Registry Run Keys / Startup Folder", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1547.004", Name: "Winlogon Helper DLL", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1543", Name: "Create or Modify System Process", TacticID: "TA0003", TacticName: "Persistence", Platforms: allPlatforms},
		{ID: "T1543.001", Name: "Launch Agent", TacticID: "TA0003", TacticName: "Persistence", Platforms: []string{"macos"}},
		{ID: "T1543.002", Name: "Systemd Service", TacticID: "TA0003", TacticName: "Persistence", Platforms: []string{"linux"}},
		{ID: "T1543.003", Name: "Windows Service", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1136", Name: "Create Account", TacticID: "TA0003", TacticName: "Persistence", Platforms: allPlatforms},
		{ID: "T1136.001", Name: "Local Account", TacticID: "TA0003", TacticName: "Persistence", Platforms: allPlatforms},
		{ID: "T1053.003", Name: "Cron", TacticID: "TA0003", TacticName: "Persistence", Platforms: linMac},
		{ID: "T1505", Name: "Server Software Component", TacticID: "TA0003", TacticName: "Persistence", Platforms: allPlatforms},
		{ID: "T1505.003", Name: "Web Shell", TacticID: "TA0003", TacticName: "Persistence", Platforms: allPlatforms},

		// TA0004 - Privilege Escalation
		{ID: "T1068", Name: "Exploitation for Privilege Escalation", TacticID: "TA0004", TacticName: "Privilege Escalation", Platforms: allPlatforms},
		{ID: "T1548", Name: "Abuse Elevation Control Mechanism", TacticID: "TA0004", TacticName: "Privilege Escalation", Platforms: allPlatforms},
		{ID: "T1548.001", Name: "Setuid and Setgid", TacticID: "TA0004", TacticName: "Privilege Escalation", Platforms: linMac},
		{ID: "T1548.002", Name: "Bypass User Account Control", TacticID: "TA0004", TacticName: "Privilege Escalation", Platforms: winOnly},
		{ID: "T1134", Name: "Access Token Manipulation", TacticID: "TA0004", TacticName: "Privilege Escalation", Platforms: winOnly},

		// TA0005 - Defense Evasion
		{ID: "T1055", Name: "Process Injection", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1055.001", Name: "Dynamic-link Library Injection", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1055.002", Name: "Portable Executable Injection", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1055.012", Name: "Process Hollowing", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1027", Name: "Obfuscated Files or Information", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1027.001", Name: "Binary Padding", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1070", Name: "Indicator Removal", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1070.001", Name: "Clear Windows Event Logs", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1070.004", Name: "File Deletion", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1562", Name: "Impair Defenses", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1562.001", Name: "Disable or Modify Tools", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1562.004", Name: "Disable or Modify System Firewall", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1112", Name: "Modify Registry", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1036", Name: "Masquerading", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1036.005", Name: "Match Legitimate Name or Location", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1218", Name: "System Binary Proxy Execution", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1218.011", Name: "Rundll32", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1140", Name: "Deobfuscate/Decode Files or Information", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1497", Name: "Virtualization/Sandbox Evasion", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1564", Name: "Hide Artifacts", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1564.001", Name: "Hidden Files and Directories", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},

		// TA0006 - Credential Access
		{ID: "T1003", Name: "OS Credential Dumping", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},
		{ID: "T1003.001", Name: "LSASS Memory", TacticID: "TA0006", TacticName: "Credential Access", Platforms: winOnly},
		{ID: "T1003.002", Name: "Security Account Manager", TacticID: "TA0006", TacticName: "Credential Access", Platforms: winOnly},
		{ID: "T1003.003", Name: "NTDS", TacticID: "TA0006", TacticName: "Credential Access", Platforms: winOnly},
		{ID: "T1003.008", Name: "/etc/passwd and /etc/shadow", TacticID: "TA0006", TacticName: "Credential Access", Platforms: []string{"linux"}},
		{ID: "T1110", Name: "Brute Force", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},
		{ID: "T1056", Name: "Input Capture", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},
		{ID: "T1056.001", Name: "Keylogging", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},
		{ID: "T1557", Name: "Adversary-in-the-Middle", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},
		{ID: "T1552", Name: "Unsecured Credentials", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},
		{ID: "T1552.001", Name: "Credentials In Files", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},

		// TA0007 - Discovery
		{ID: "T1082", Name: "System Information Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1018", Name: "Remote System Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1049", Name: "System Network Connections Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1057", Name: "Process Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1083", Name: "File and Directory Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1016", Name: "System Network Configuration Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1033", Name: "System Owner/User Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1087", Name: "Account Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1087.001", Name: "Local Account", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1135", Name: "Network Share Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1069", Name: "Permission Groups Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1012", Name: "Query Registry", TacticID: "TA0007", TacticName: "Discovery", Platforms: winOnly},
		{ID: "T1518", Name: "Software Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},

		// TA0008 - Lateral Movement
		{ID: "T1021", Name: "Remote Services", TacticID: "TA0008", TacticName: "Lateral Movement", Platforms: allPlatforms},
		{ID: "T1021.001", Name: "Remote Desktop Protocol", TacticID: "TA0008", TacticName: "Lateral Movement", Platforms: winOnly},
		{ID: "T1021.002", Name: "SMB/Windows Admin Shares", TacticID: "TA0008", TacticName: "Lateral Movement", Platforms: winOnly},
		{ID: "T1021.004", Name: "SSH", TacticID: "TA0008", TacticName: "Lateral Movement", Platforms: linMac},
		{ID: "T1570", Name: "Lateral Tool Transfer", TacticID: "TA0008", TacticName: "Lateral Movement", Platforms: allPlatforms},
		{ID: "T1563", Name: "Remote Service Session Hijacking", TacticID: "TA0008", TacticName: "Lateral Movement", Platforms: allPlatforms},

		// TA0009 - Collection
		{ID: "T1005", Name: "Data from Local System", TacticID: "TA0009", TacticName: "Collection", Platforms: allPlatforms},
		{ID: "T1039", Name: "Data from Network Shared Drive", TacticID: "TA0009", TacticName: "Collection", Platforms: allPlatforms},
		{ID: "T1113", Name: "Screen Capture", TacticID: "TA0009", TacticName: "Collection", Platforms: allPlatforms},
		{ID: "T1119", Name: "Automated Collection", TacticID: "TA0009", TacticName: "Collection", Platforms: allPlatforms},
		{ID: "T1074", Name: "Data Staged", TacticID: "TA0009", TacticName: "Collection", Platforms: allPlatforms},
		{ID: "T1560", Name: "Archive Collected Data", TacticID: "TA0009", TacticName: "Collection", Platforms: allPlatforms},

		// TA0010 - Exfiltration
		{ID: "T1041", Name: "Exfiltration Over C2 Channel", TacticID: "TA0010", TacticName: "Exfiltration", Platforms: allPlatforms},
		{ID: "T1048", Name: "Exfiltration Over Alternative Protocol", TacticID: "TA0010", TacticName: "Exfiltration", Platforms: allPlatforms},
		{ID: "T1567", Name: "Exfiltration Over Web Service", TacticID: "TA0010", TacticName: "Exfiltration", Platforms: allPlatforms},
		{ID: "T1020", Name: "Automated Exfiltration", TacticID: "TA0010", TacticName: "Exfiltration", Platforms: allPlatforms},
		{ID: "T1537", Name: "Transfer Data to Cloud Account", TacticID: "TA0010", TacticName: "Exfiltration", Platforms: allPlatforms},

		// TA0011 - Command and Control
		{ID: "T1071", Name: "Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1071.001", Name: "Web Protocols", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1071.004", Name: "DNS", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1105", Name: "Ingress Tool Transfer", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1572", Name: "Protocol Tunneling", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1573", Name: "Encrypted Channel", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1573.001", Name: "Symmetric Cryptography", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1095", Name: "Non-Application Layer Protocol", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1571", Name: "Non-Standard Port", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1090", Name: "Proxy", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1102", Name: "Web Service", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1568", Name: "Dynamic Resolution", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1132", Name: "Data Encoding", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},

		// TA0040 - Impact
		{ID: "T1486", Name: "Data Encrypted for Impact", TacticID: "TA0040", TacticName: "Impact", Platforms: allPlatforms},
		{ID: "T1489", Name: "Service Stop", TacticID: "TA0040", TacticName: "Impact", Platforms: winLinux},
		{ID: "T1490", Name: "Inhibit System Recovery", TacticID: "TA0040", TacticName: "Impact", Platforms: allPlatforms},
		{ID: "T1485", Name: "Data Destruction", TacticID: "TA0040", TacticName: "Impact", Platforms: allPlatforms},
		{ID: "T1529", Name: "System Shutdown/Reboot", TacticID: "TA0040", TacticName: "Impact", Platforms: allPlatforms},
		{ID: "T1491", Name: "Defacement", TacticID: "TA0040", TacticName: "Impact", Platforms: allPlatforms},
		{ID: "T1496", Name: "Resource Hijacking", TacticID: "TA0040", TacticName: "Impact", Platforms: allPlatforms},
		{ID: "T1561", Name: "Disk Wipe", TacticID: "TA0040", TacticName: "Impact", Platforms: allPlatforms},

		// Techniques cited by rules/sigma that this table did not list.
		//
		// MapSigmaTag now reports a well-formed technique ID whether or
		// not it is here, so a gap no longer means an empty MITRE
		// slice. What it still means is a missing technique name and,
		// for a technique with no known parent, a tactic that has to be
		// inferred from the rule's own tactic tag. These 64 entries
		// close the gap for the corpus as it stands:
		// TestSigmaCorpusTagsAllMapToTechniques walks every .yml under
		// rules/sigma and fails on a tag that still resolves to no
		// technique name, so adding a rule for an unlisted technique
		// says so here rather than shipping a half-attributed alert.
		//
		// Tactic is the primary ATT&CK tactic for each technique. A
		// handful (T1484, T1556, T1574) are listed under two or three
		// tactics upstream; the one recorded is the tactic these rules
		// detect them under, which is also what MapSigmaTags would
		// otherwise take from the rule tag.
		{ID: "T1595.002", Name: "Vulnerability Scanning", TacticID: "TA0043", TacticName: "Reconnaissance", Platforms: allPlatforms},
		{ID: "T1098", Name: "Account Manipulation", TacticID: "TA0003", TacticName: "Persistence", Platforms: allPlatforms},
		{ID: "T1098.004", Name: "SSH Authorized Keys", TacticID: "TA0003", TacticName: "Persistence", Platforms: linMac},
		{ID: "T1037.001", Name: "Logon Script (Windows)", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1137", Name: "Office Application Startup", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1176", Name: "Browser Extensions", TacticID: "TA0003", TacticName: "Persistence", Platforms: allPlatforms},
		{ID: "T1542.003", Name: "Bootkit", TacticID: "TA0003", TacticName: "Persistence", Platforms: winLinux},
		{ID: "T1546", Name: "Event Triggered Execution", TacticID: "TA0003", TacticName: "Persistence", Platforms: allPlatforms},
		{ID: "T1546.001", Name: "Change Default File Association", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1546.002", Name: "Screensaver", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1546.003", Name: "Windows Management Instrumentation Event Subscription", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1546.004", Name: "Unix Shell Configuration Modification", TacticID: "TA0003", TacticName: "Persistence", Platforms: linMac},
		{ID: "T1546.007", Name: "Netsh Helper DLL", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1546.008", Name: "Accessibility Features", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1546.011", Name: "Application Shimming", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1546.012", Name: "Image File Execution Options Injection", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1546.015", Name: "Component Object Model Hijacking", TacticID: "TA0003", TacticName: "Persistence", Platforms: winOnly},
		{ID: "T1554", Name: "Compromise Host Software Binary", TacticID: "TA0003", TacticName: "Persistence", Platforms: allPlatforms},
		{ID: "T1574", Name: "Hijack Execution Flow", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1574.001", Name: "DLL Search Order Hijacking", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1574.002", Name: "DLL Side-Loading", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1574.006", Name: "Dynamic Linker Hijacking", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: linMac},
		{ID: "T1574.010", Name: "Services File Permissions Weakness", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1574.011", Name: "Services Registry Permissions Weakness", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1484", Name: "Domain or Tenant Policy Modification", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1014", Name: "Rootkit", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1197", Name: "BITS Jobs", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1202", Name: "Indirect Command Execution", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1220", Name: "XSL Script Processing", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1221", Name: "Template Injection", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: winOnly},
		{ID: "T1222", Name: "File and Directory Permissions Modification", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1222.002", Name: "Linux and Mac File and Directory Permissions Modification", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: linMac},
		{ID: "T1480", Name: "Execution Guardrails", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1480.001", Name: "Environmental Keying", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1553", Name: "Subvert Trust Controls", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1553.001", Name: "Gatekeeper Bypass", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: macOnly},
		{ID: "T1553.002", Name: "Code Signing", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: allPlatforms},
		{ID: "T1610", Name: "Deploy Container", TacticID: "TA0005", TacticName: "Defense Evasion", Platforms: linuxOnly},
		{ID: "T1611", Name: "Escape to Host", TacticID: "TA0004", TacticName: "Privilege Escalation", Platforms: linuxOnly},
		{ID: "T1648", Name: "Serverless Execution", TacticID: "TA0002", TacticName: "Execution", Platforms: allPlatforms},
		{ID: "T1129", Name: "Shared Modules", TacticID: "TA0002", TacticName: "Execution", Platforms: allPlatforms},
		{ID: "T1559", Name: "Inter-Process Communication", TacticID: "TA0002", TacticName: "Execution", Platforms: allPlatforms},
		{ID: "T1559.001", Name: "Component Object Model", TacticID: "TA0002", TacticName: "Execution", Platforms: winOnly},
		{ID: "T1555", Name: "Credentials from Password Stores", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},
		{ID: "T1555.001", Name: "Keychain", TacticID: "TA0006", TacticName: "Credential Access", Platforms: macOnly},
		{ID: "T1555.003", Name: "Credentials from Web Browsers", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},
		{ID: "T1556", Name: "Modify Authentication Process", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},
		{ID: "T1539", Name: "Steal Web Session Cookie", TacticID: "TA0006", TacticName: "Credential Access", Platforms: allPlatforms},
		{ID: "T1558.003", Name: "Kerberoasting", TacticID: "TA0006", TacticName: "Credential Access", Platforms: winOnly},
		{ID: "T1558.004", Name: "AS-REP Roasting", TacticID: "TA0006", TacticName: "Credential Access", Platforms: winOnly},
		{ID: "T1007", Name: "System Service Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1046", Name: "Network Service Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1120", Name: "Peripheral Device Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1614", Name: "System Location Discovery", TacticID: "TA0007", TacticName: "Discovery", Platforms: allPlatforms},
		{ID: "T1205.001", Name: "Port Knocking", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1001", Name: "Data Obfuscation", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1008", Name: "Fallback Channels", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1104", Name: "Multi-Stage Channels", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1219", Name: "Remote Access Software", TacticID: "TA0011", TacticName: "Command and Control", Platforms: allPlatforms},
		{ID: "T1029", Name: "Scheduled Transfer", TacticID: "TA0010", TacticName: "Exfiltration", Platforms: allPlatforms},
		{ID: "T1030", Name: "Data Transfer Size Limits", TacticID: "TA0010", TacticName: "Exfiltration", Platforms: allPlatforms},
		{ID: "T1548.003", Name: "Sudo and Sudo Caching", TacticID: "TA0004", TacticName: "Privilege Escalation", Platforms: linMac},
		{ID: "T1531", Name: "Account Access Removal", TacticID: "TA0040", TacticName: "Impact", Platforms: allPlatforms},
		{ID: "T1565.001", Name: "Stored Data Manipulation", TacticID: "TA0040", TacticName: "Impact", Platforms: allPlatforms},
	}

	for i := range defs {
		t := &defs[i]
		m.techniques[t.ID] = t
		m.tagMap[strings.ToLower(t.ID)] = t.ID
		dotted := strings.ReplaceAll(strings.ToLower(t.ID), ".", ".")
		if dotted != strings.ToLower(t.ID) {
			m.tagMap[dotted] = t.ID
		}
	}
}

// MapSigmaTag converts a Sigma tag (e.g., "attack.t1059.001" or "attack.initial_access")
// to a MITREAttack reference. Returns nil if the tag is not recognized.
func (m *MITREMapper) MapSigmaTag(tag string) *events.MITREAttack {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if !strings.HasPrefix(tag, "attack.") {
		return nil
	}
	value := strings.TrimPrefix(tag, "attack.")
	// Sigma tactic tags appear both hyphenated and underscored —
	// "attack.privilege-escalation" and "attack.privilege_escalation" are
	// the same tactic, and the corpus contains both. tagMap is keyed with
	// underscores, so a hyphenated tag used to miss and the rule lost its
	// tactic for no reason an author could have seen.
	value = strings.ReplaceAll(value, "-", "_")

	if id, ok := m.tagMap[value]; ok {
		if strings.HasPrefix(id, "TA") {
			name := m.tactics[id]
			return &events.MITREAttack{
				TacticID:   id,
				TacticName: name,
			}
		}
		if tech, ok := m.techniques[id]; ok {
			return &events.MITREAttack{
				TechniqueID:   tech.ID,
				TechniqueName: tech.Name,
				TacticID:      tech.TacticID,
				TacticName:    tech.TacticName,
			}
		}
	}

	// Try direct technique ID lookup (handles case variations).
	upper := strings.ToUpper(value)
	if tech, ok := m.techniques[upper]; ok {
		return &events.MITREAttack{
			TechniqueID:   tech.ID,
			TechniqueName: tech.Name,
			TacticID:      tech.TacticID,
			TacticName:    tech.TacticName,
		}
	}

	// A well-formed technique tag the table does not list still yields its
	// ID. Returning nil here was the single biggest hole in ATT&CK
	// attribution: 113 of the 216 distinct technique tags across
	// rules/sigma named techniques absent from initTechniques, so every
	// alert from those rules shipped with an empty MITRE slice.
	//
	// For an unknown sub-technique the parent is consulted. ATT&CK
	// sub-techniques always sit under their parent's tactic, so inheriting
	// the parent's tactic is a fact about the model and not a guess; the
	// parent's name is carried too, because "Hijack Execution Flow" on
	// T1574.004 is more use to an analyst than a bare ID.
	id, ok := canonicalTechniqueID(value)
	if !ok {
		return nil
	}
	out := &events.MITREAttack{TechniqueID: id}
	if parent, _, isSub := strings.Cut(id, "."); isSub {
		if pt, pok := m.techniques[parent]; pok {
			out.TechniqueName = pt.Name
			out.TacticID = pt.TacticID
			out.TacticName = pt.TacticName
		}
	}
	return out
}

// MapSigmaTags maps every attack tag on one rule, resolving each technique's
// tactic from the rule's own tactic tag when the technique table cannot supply
// one.
//
// Per-tag mapping alone cannot do this: "attack.t1546.013" and
// "attack.persistence" are separate tags, and only together do they say which
// tactic the technique was cited under. Mapping them one at a time produced an
// alert carrying a tactic-only entry with no technique next to a technique
// entry with no tactic, and every consumer that keys on TechniqueID (the
// dedup key in internal/detection/dedup.go, the technique dedup in
// engine.go, the validation suite's match) saw the first as a duplicate empty
// string.
//
// A tactic-only result is returned only when the rule cites no technique at
// all, which is the one case where it is the whole of what the rule claims.
func (m *MITREMapper) MapSigmaTags(tags []string) []events.MITREAttack {
	var techniques []events.MITREAttack
	var tacticID, tacticName string

	for _, tag := range tags {
		mt := m.MapSigmaTag(tag)
		if mt == nil {
			continue
		}
		if mt.TechniqueID == "" {
			// A tactic tag. First one wins: a rule citing two
			// tactics has no way to say which technique belongs to
			// which, and inventing an answer would be worse than
			// attributing to the one it named first.
			if tacticID == "" {
				tacticID, tacticName = mt.TacticID, mt.TacticName
			}
			continue
		}
		techniques = append(techniques, *mt)
	}

	for i := range techniques {
		if techniques[i].TacticID == "" {
			techniques[i].TacticID = tacticID
			techniques[i].TacticName = tacticName
		}
	}
	if len(techniques) == 0 && tacticID != "" {
		return []events.MITREAttack{{TacticID: tacticID, TacticName: tacticName}}
	}
	return techniques
}

// MapTechnique looks up a MITRE ATT&CK technique by its ID (e.g., "T1059.001").
func (m *MITREMapper) MapTechnique(id string) *events.MITREAttack {
	tech, ok := m.techniques[strings.ToUpper(strings.TrimSpace(id))]
	if !ok {
		return nil
	}
	return &events.MITREAttack{
		TechniqueID:   tech.ID,
		TechniqueName: tech.Name,
		TacticID:      tech.TacticID,
		TacticName:    tech.TacticName,
	}
}

// MapTacticName converts a human-readable tactic name (e.g., "initial_access")
// to its canonical ATT&CK tactic ID (e.g., "TA0001"). Returns an empty string
// if the tactic is not recognized.
func (m *MITREMapper) MapTacticName(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.ReplaceAll(key, " ", "_")
	if id, ok := m.tagMap[key]; ok && strings.HasPrefix(id, "TA") {
		return id
	}
	return ""
}

// CoverageByTags returns sorted technique IDs inferred from Sigma-style tags.
func (m *MITREMapper) CoverageByTags(tags []string) []string {
	seen := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		mt := m.MapSigmaTag(t)
		if mt == nil || mt.TechniqueID == "" {
			continue
		}
		seen[mt.TechniqueID] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
