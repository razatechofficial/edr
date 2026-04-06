package detection

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/razatechofficial/edr/pkg/events"
	"go.uber.org/zap"
)

const (
	entropyThreshold = 7.2
	massOpThreshold  = 50
	ransomSignalMin  = 3
)

type ransomwareScore struct {
	highEntropy  bool
	massFileOps  bool
	extChange    bool
	shadowDelete bool
	bcdeditMod   bool
	ransomNote   bool
	alertFired   bool
}

func (s *ransomwareScore) count() int {
	n := 0
	for _, b := range []bool{s.highEntropy, s.massFileOps, s.extChange, s.shadowDelete, s.bcdeditMod, s.ransomNote} {
		if b {
			n++
		}
	}
	return n
}

func (s *ransomwareScore) signalNames() []string {
	var out []string
	if s.highEntropy {
		out = append(out, "high_entropy_writes")
	}
	if s.massFileOps {
		out = append(out, "mass_file_operations")
	}
	if s.extChange {
		out = append(out, "extension_changes")
	}
	if s.shadowDelete {
		out = append(out, "shadow_copy_deletion")
	}
	if s.bcdeditMod {
		out = append(out, "boot_recovery_modification")
	}
	if s.ransomNote {
		out = append(out, "ransom_note_created")
	}
	return out
}

// RansomwareDetector identifies ransomware behavior through multi-signal
// correlation: file entropy, mass operations, extension changes, shadow copy
// deletion, boot recovery modification, and ransom note file patterns.
// Three or more concurrent signals trigger a critical alert with an automatic
// kill-and-isolate recommendation.
type RansomwareDetector struct {
	mu     sync.Mutex
	logger *zap.Logger
	scores map[uint32]*ransomwareScore
}

// NewRansomwareDetector creates a RansomwareDetector.
func NewRansomwareDetector(logger *zap.Logger) *RansomwareDetector {
	return &RansomwareDetector{
		logger: logger,
		scores: make(map[uint32]*ransomwareScore),
	}
}

// Name returns the detector identifier.
func (d *RansomwareDetector) Name() string { return "ransomware" }

// Analyze evaluates file and process events for ransomware indicators and
// returns alerts when the combined signal score exceeds the threshold.
func (d *RansomwareDetector) Analyze(event interface{}, correlator *Correlator) []*events.Alert {
	pid := extractPID(event)
	if pid == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	sc := d.scores[pid]
	if sc == nil {
		sc = &ransomwareScore{}
		d.scores[pid] = sc
	}
	if sc.alertFired {
		return nil
	}

	d.checkFileIndicators(event, sc)
	d.checkProcessIndicators(event, sc)
	d.checkFileContent(event, sc)

	recentFiles := correlator.GetRecentFiles(pid, Window1m)
	if len(recentFiles) > massOpThreshold {
		sc.massFileOps = true
	}

	n := sc.count()
	if n >= ransomSignalMin {
		sc.alertFired = true
		d.logger.Warn("ransomware activity confirmed",
			zap.Uint32("pid", pid), zap.Int("signals", n),
			zap.Strings("indicators", sc.signalNames()))
		return []*events.Alert{newAlert(
			"RANSOM-001", "ransomware", "Ransomware activity detected",
			fmt.Sprintf("PID %d triggered %d/6 ransomware indicators: %s",
				pid, n, strings.Join(sc.signalNames(), ", ")),
			events.SeverityCritical,
			[]events.MITREAttack{
				{TechniqueID: "T1486", TechniqueName: "Data Encrypted for Impact", TacticID: "TA0040", TacticName: "Impact"},
				{TechniqueID: "T1490", TechniqueName: "Inhibit System Recovery", TacticID: "TA0040", TacticName: "Impact"},
			},
			[]string{"ransomware", "action:kill_process", "action:host_isolate"}, event,
		)}
	}
	if n == 2 {
		d.logger.Info("possible ransomware preparation",
			zap.Uint32("pid", pid), zap.Strings("indicators", sc.signalNames()))
		return []*events.Alert{newAlert(
			"RANSOM-002", "ransomware", "Possible ransomware preparation",
			fmt.Sprintf("PID %d shows %d ransomware indicators: %s",
				pid, n, strings.Join(sc.signalNames(), ", ")),
			events.SeverityHigh,
			[]events.MITREAttack{
				{TechniqueID: "T1486", TechniqueName: "Data Encrypted for Impact", TacticID: "TA0040", TacticName: "Impact"},
			},
			[]string{"ransomware", "action:kill_process"}, event,
		)}
	}
	return nil
}

// Reset clears all tracked state.
func (d *RansomwareDetector) Reset() {
	d.mu.Lock()
	d.scores = make(map[uint32]*ransomwareScore)
	d.mu.Unlock()
}

func (d *RansomwareDetector) checkFileIndicators(event interface{}, sc *ransomwareScore) {
	path := extractFilePath(event)
	if path == "" {
		return
	}
	op := strings.ToLower(extractFileOperation(event))

	if op == "rename" {
		ext := strings.ToLower(filepath.Ext(path))
		if containsAny(ext, ".encrypted", ".locked", ".crypt", ".enc", ".crypted",
			".locky", ".cerber", ".zepto", ".thor", ".aesir", ".zzzzz", ".wncry") {
			sc.extChange = true
		}
	}

	if op == "create" || op == "write" {
		base := strings.ToLower(filepath.Base(path))
		if containsAny(base, "readme.txt", "decrypt", "how_to_", "recover_",
			"help_decrypt", "restore_files", "!readme!", "_readme_",
			"ransom", "your_files", "read_me.txt") {
			sc.ransomNote = true
		}
	}
}

func (d *RansomwareDetector) checkProcessIndicators(event interface{}, sc *ransomwareScore) {
	cmd := strings.ToLower(extractCommandLine(event))
	if cmd == "" {
		return
	}
	if containsAny(cmd, "vssadmin delete shadows", "vssadmin.exe delete shadows",
		"wmic shadowcopy delete", "wmic.exe shadowcopy delete",
		"wbadmin delete catalog", "wbadmin delete systemstatebackup") {
		sc.shadowDelete = true
	}
	if containsAny(cmd, "bcdedit /set", "bcdedit.exe /set") &&
		containsAny(cmd, "recoveryenabled no", "bootstatuspolicy ignoreallfailures") {
		sc.bcdeditMod = true
	}
}

func (d *RansomwareDetector) checkFileContent(event interface{}, sc *ransomwareScore) {
	m, ok := event.(map[string]interface{})
	if !ok {
		return
	}
	content, ok := m["content"]
	if !ok {
		return
	}
	var data []byte
	switch v := content.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	}
	if len(data) > 0 && shannonEntropy(data) > entropyThreshold {
		sc.highEntropy = true
	}
}

var knownRansomwareExtensions = []string{
	".encrypted", ".locked", ".crypt", ".enc", ".crypted",
	".locky", ".cerber", ".zepto", ".thor", ".aesir",
	".zzzzz", ".wncry", ".wcry", ".wcryt",
}
