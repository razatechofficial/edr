package detection

import (
	"strings"
	"sync"
	"time"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

// SequenceStep defines a single step in an attack sequence with a matching
// predicate and maximum allowed time since the previous step matched.
type SequenceStep struct {
	Name    string
	Matcher func(event interface{}) bool
	MaxWait time.Duration
}

// Sequence defines an ordered multi-step attack pattern (kill chain).
type Sequence struct {
	ID          string
	Name        string
	Description string
	Steps       []SequenceStep
	Severity    events.Severity
	MITRE       []events.MITREAttack
	Tags        []string
}

type sequenceState struct {
	currentStep   int
	lastMatch     time.Time
	startTime     time.Time
	matchedEvents []interface{}
}

// SequenceEngine detects multi-step attack patterns by tracking ordered event
// sequences per entity (PID). It acts as a state machine that advances through
// sequence steps and fires alerts on full-chain completion.
type SequenceEngine struct {
	sequences []*Sequence
	// states maps sequence ID → PID → tracking state
	states map[string]map[uint32]*sequenceState
	mu     sync.Mutex
	logger *zap.Logger
}

// NewSequenceEngine creates a SequenceEngine with built-in attack sequences
// for credential dump chains, persistence installation, and ransomware preparation.
func NewSequenceEngine(logger *zap.Logger) *SequenceEngine {
	se := &SequenceEngine{
		states: make(map[string]map[uint32]*sequenceState),
		logger: logger,
	}
	se.registerBuiltinSequences()
	return se
}

// Name returns the detector identifier.
func (se *SequenceEngine) Name() string { return "sequence_engine" }

// Analyze evaluates an event against all registered attack sequences and
// returns alerts for any completed chains.
func (se *SequenceEngine) Analyze(event interface{}, _ *Correlator) []*events.Alert {
	pid := extractPID(event)
	now := time.Now()

	se.mu.Lock()
	defer se.mu.Unlock()

	var alerts []*events.Alert
	for _, seq := range se.sequences {
		pidStates, ok := se.states[seq.ID]
		if !ok {
			pidStates = make(map[uint32]*sequenceState)
			se.states[seq.ID] = pidStates
		}

		st, ok := pidStates[pid]
		if !ok {
			st = &sequenceState{}
			pidStates[pid] = st
		}

		if st.currentStep > 0 && now.Sub(st.lastMatch) > seq.Steps[st.currentStep].MaxWait {
			*st = sequenceState{}
		}

		if !seq.Steps[st.currentStep].Matcher(event) {
			continue
		}

		if st.currentStep == 0 {
			st.startTime = now
		}
		st.lastMatch = now
		st.matchedEvents = append(st.matchedEvents, event)
		st.currentStep++

		se.logger.Debug("sequence step matched",
			zap.String("sequence", seq.ID),
			zap.String("step", seq.Steps[st.currentStep-1].Name),
			zap.Uint32("pid", pid),
			zap.Int("progress", st.currentStep),
			zap.Int("total", len(seq.Steps)),
		)

		if st.currentStep >= len(seq.Steps) {
			alerts = append(alerts, newAlert(
				seq.ID, seq.Name, seq.Name, seq.Description,
				seq.Severity, seq.MITRE, seq.Tags, st.matchedEvents,
			))
			*st = sequenceState{}
		}
	}
	return alerts
}

// Reset clears all tracked sequence state.
func (se *SequenceEngine) Reset() {
	se.mu.Lock()
	se.states = make(map[string]map[uint32]*sequenceState)
	se.mu.Unlock()
}

// AddSequence registers a custom attack sequence for detection.
func (se *SequenceEngine) AddSequence(seq *Sequence) {
	se.mu.Lock()
	se.sequences = append(se.sequences, seq)
	se.mu.Unlock()
}

func (se *SequenceEngine) registerBuiltinSequences() {
	se.sequences = []*Sequence{
		{
			ID:          "SEQ-CRED-CHAIN",
			Name:        "Credential Dump Kill Chain",
			Description: "Credential theft followed by network discovery and lateral movement",
			Steps: []SequenceStep{
				{Name: "credential_access", Matcher: seqMatchCredAccess, MaxWait: time.Hour},
				{Name: "discovery", Matcher: seqMatchDiscovery, MaxWait: time.Hour},
				{Name: "lateral_movement", Matcher: seqMatchLateral, MaxWait: 2 * time.Hour},
			},
			Severity: events.SeverityCritical,
			MITRE: []events.MITREAttack{
				{TechniqueID: "T1003", TechniqueName: "OS Credential Dumping", TacticID: "TA0006", TacticName: "Credential Access"},
				{TechniqueID: "T1087", TechniqueName: "Account Discovery", TacticID: "TA0007", TacticName: "Discovery"},
				{TechniqueID: "T1021", TechniqueName: "Remote Services", TacticID: "TA0008", TacticName: "Lateral Movement"},
			},
			Tags: []string{"kill_chain", "credential_dump", "lateral_movement", "action:host_isolate"},
		},
		{
			ID:          "SEQ-PERSIST-CHAIN",
			Name:        "Persistence Installation Sequence",
			Description: "Binary drop followed by persistence mechanism installation and execution",
			Steps: []SequenceStep{
				{Name: "binary_drop", Matcher: seqMatchBinaryDrop, MaxWait: 5 * time.Minute},
				{Name: "persistence_install", Matcher: seqMatchPersistInstall, MaxWait: 10 * time.Minute},
				{Name: "execution", Matcher: seqMatchSuspiciousExec, MaxWait: 30 * time.Minute},
			},
			Severity: events.SeverityHigh,
			MITRE: []events.MITREAttack{
				{TechniqueID: "T1105", TechniqueName: "Ingress Tool Transfer", TacticID: "TA0011", TacticName: "Command and Control"},
				{TechniqueID: "T1053", TechniqueName: "Scheduled Task/Job", TacticID: "TA0003", TacticName: "Persistence"},
			},
			Tags: []string{"kill_chain", "persistence", "action:quarantine_file"},
		},
		{
			ID:          "SEQ-RANSOM-CHAIN",
			Name:        "Ransomware Preparation Sequence",
			Description: "Backup destruction followed by mass file operations and ransom note creation",
			Steps: []SequenceStep{
				{Name: "backup_destruction", Matcher: seqMatchBackupDestroy, MaxWait: 30 * time.Minute},
				{Name: "mass_file_ops", Matcher: seqMatchMassFileOp, MaxWait: time.Hour},
				{Name: "ransom_note", Matcher: seqMatchRansomNote, MaxWait: 2 * time.Hour},
			},
			Severity: events.SeverityCritical,
			MITRE: []events.MITREAttack{
				{TechniqueID: "T1490", TechniqueName: "Inhibit System Recovery", TacticID: "TA0040", TacticName: "Impact"},
				{TechniqueID: "T1486", TechniqueName: "Data Encrypted for Impact", TacticID: "TA0040", TacticName: "Impact"},
			},
			Tags: []string{"kill_chain", "ransomware", "action:kill_process", "action:host_isolate"},
		},
	}
}

// ---------------------------------------------------------------------------
// Sequence step matchers
// ---------------------------------------------------------------------------

func seqMatchCredAccess(event interface{}) bool {
	cmd := strings.ToLower(extractCommandLine(event))
	path := strings.ToLower(extractFilePath(event))
	proc := strings.ToLower(extractProcessName(event))
	return containsAny(cmd, "mimikatz", "secretsdump", "hashdump", "gsecdump", "lsadump", "procdump -ma lsass") ||
		containsAny(path, "lsass", "\\config\\sam", "ntds.dit", "/etc/shadow") ||
		containsAny(proc, "mimikatz", "secretsdump", "gsecdump")
}

func seqMatchDiscovery(event interface{}) bool {
	cmd := strings.ToLower(extractCommandLine(event))
	return containsAny(cmd,
		"net user", "net group", "net localgroup", "whoami", "ipconfig /all",
		"systeminfo", "nltest", "dsquery", "arp -a", "net view", "net share",
		"cat /etc/passwd", "id ", "uname -a", "ifconfig", "ip addr")
}

func seqMatchLateral(event interface{}) bool {
	cmd := strings.ToLower(extractCommandLine(event))
	port := extractDestPort(event)
	proc := strings.ToLower(extractProcessName(event))
	return containsAny(cmd, "psexec", "wmic /node:", "enter-pssession", "invoke-command", "winrm", "evil-winrm") ||
		port == 445 || port == 5985 || port == 5986 ||
		containsAny(proc, "psexec", "psexesvc")
}

func seqMatchBinaryDrop(event interface{}) bool {
	op := strings.ToLower(extractFileOperation(event))
	if op != "create" && op != "write" {
		return false
	}
	return containsAny(strings.ToLower(extractFilePath(event)),
		"/tmp/", "\\temp\\", "\\appdata\\", "/dev/shm/", "\\downloads\\", "/var/tmp/")
}

func seqMatchPersistInstall(event interface{}) bool {
	cmd := strings.ToLower(extractCommandLine(event))
	path := strings.ToLower(extractFilePath(event))
	return containsAny(cmd, "schtasks /create", "sc create", "reg add", "crontab", "systemctl enable", "launchctl load") ||
		containsAny(path, "cron.d/", "systemd/system/", "launchdaemons/", "launchagents/", "\\run\\", "\\runonce\\", "startup\\")
}

func seqMatchSuspiciousExec(event interface{}) bool {
	path := strings.ToLower(extractFilePath(event))
	proc := strings.ToLower(extractProcessName(event))
	return (proc != "" && containsAny(path, "/tmp/", "\\temp\\", "\\appdata\\", "/dev/shm/")) ||
		containsAny(proc, "svchost", "rundll32", "regsvr32", "mshta")
}

func seqMatchBackupDestroy(event interface{}) bool {
	cmd := strings.ToLower(extractCommandLine(event))
	return containsAny(cmd,
		"vssadmin delete shadows", "wmic shadowcopy delete",
		"bcdedit /set", "wbadmin delete catalog", "delete systemstatebackup")
}

func seqMatchMassFileOp(event interface{}) bool {
	op := strings.ToLower(extractFileOperation(event))
	return op == "write" || op == "rename" || op == "modify" || op == "create"
}

func seqMatchRansomNote(event interface{}) bool {
	op := strings.ToLower(extractFileOperation(event))
	if op != "create" && op != "write" {
		return false
	}
	return containsAny(strings.ToLower(extractFilePath(event)),
		"readme.txt", "decrypt", "how_to_", "recover_", "help_decrypt",
		"restore_files", "!readme!", "_readme_", "ransom")
}
