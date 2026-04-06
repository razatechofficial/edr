package features

import (
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

const defaultWindowSize = 50

// BehavioralFeatureExtractor converts event sequences to LSTM input matrices.
type BehavioralFeatureExtractor struct {
	windowSize int
}

// NewBehavioralFeatureExtractor creates an extractor with the given window size.
// A window of 50 events yields 48×50 = 2400 features.
func NewBehavioralFeatureExtractor(windowSize int) *BehavioralFeatureExtractor {
	if windowSize <= 0 {
		windowSize = defaultWindowSize
	}
	return &BehavioralFeatureExtractor{windowSize: windowSize}
}

// Extract converts an event window into a flat feature vector suitable for
// LSTM inference. Each event is encoded as a 48-dimensional sub-vector:
//
//	[event_type(25), process_category(8), privilege_level(3),
//	 network_flag(1), file_write_flag(1), registry_flag(1),
//	 time_of_day(1), day_of_week(7), parent_relationship_score(1)]
func (e *BehavioralFeatureExtractor) Extract(eventWindow []interface{}) []float32 {
	feats := make([]float32, e.windowSize*FeaturesPerEvent)
	for i := 0; i < e.windowSize && i < len(eventWindow); i++ {
		e.encodeEvent(feats, i*FeaturesPerEvent, eventWindow[i])
	}
	return feats
}

// WindowSize returns the configured event window size.
func (e *BehavioralFeatureExtractor) WindowSize() int { return e.windowSize }

func (e *BehavioralFeatureExtractor) encodeEvent(dst []float32, offset int, event interface{}) {
	var (
		subtype      string
		category     string
		privilege    string
		networkFlag  float32
		fileWrite    float32
		registryFlag float32
		ts           time.Time
		parentScore  float32
	)

	switch ev := event.(type) {
	case *schema.ProcessEvent:
		subtype = "process_create"
		category = classifyProcessName(ev.ProcessName)
		privilege = inferPrivilege(ev.User)
		ts = ev.Timestamp
		parentScore = parentRelationshipScore(ev.PPID, ev.PID)
	case schema.ProcessEvent:
		subtype = "process_create"
		category = classifyProcessName(ev.ProcessName)
		privilege = inferPrivilege(ev.User)
		ts = ev.Timestamp
		parentScore = parentRelationshipScore(ev.PPID, ev.PID)

	case *schema.FileEvent:
		subtype = fileOperationSubtype(ev.Operation)
		category = "unknown"
		privilege = "low"
		if ev.Operation == "write" || ev.Operation == "create" {
			fileWrite = 1.0
		}
		ts = ev.Timestamp
	case schema.FileEvent:
		subtype = fileOperationSubtype(ev.Operation)
		category = "unknown"
		privilege = "low"
		if ev.Operation == "write" || ev.Operation == "create" {
			fileWrite = 1.0
		}
		ts = ev.Timestamp

	case *schema.NetworkEvent:
		subtype = "network_connect"
		category = "unknown"
		privilege = "low"
		networkFlag = 1.0
		ts = ev.Timestamp
	case schema.NetworkEvent:
		subtype = "network_connect"
		category = "unknown"
		privilege = "low"
		networkFlag = 1.0
		ts = ev.Timestamp

	case *schema.AuthEvent:
		subtype = authSubtype(ev.Outcome)
		category = "system"
		privilege = "high"
		ts = ev.Timestamp
	case schema.AuthEvent:
		subtype = authSubtype(ev.Outcome)
		category = "system"
		privilege = "high"
		ts = ev.Timestamp

	default:
		return
	}

	pos := offset
	OneHotEventType(dst, pos, subtype)
	pos += numEventSubtypes

	OneHotProcessCategory(dst, pos, category)
	pos += numProcessCats

	EncodePrivilegeLevel(dst, pos, privilege)
	pos += numPrivLevels

	dst[pos] = networkFlag
	pos++
	dst[pos] = fileWrite
	pos++
	dst[pos] = registryFlag
	pos++

	dst[pos] = NormalizeTimeOfDay(ts)
	pos++

	EncodeDayOfWeek(dst, pos, ts)
	pos += 7

	dst[pos] = parentScore
}

func classifyProcessName(name string) string {
	switch {
	case isInSet(name, "bash", "sh", "zsh", "fish", "cmd.exe", "powershell.exe", "pwsh"):
		return "shell"
	case isInSet(name, "chrome", "firefox", "safari", "msedge", "opera", "brave"):
		return "browser"
	case isInSet(name, "init", "systemd", "svchost.exe", "launchd", "kernel"):
		return "system"
	case isInSet(name, "python", "python3", "node", "ruby", "perl", "lua"):
		return "scripting"
	case isInSet(name, "gcc", "g++", "clang", "rustc", "javac", "go"):
		return "compiler"
	case isInSet(name, "gdb", "lldb", "strace", "ltrace", "dtrace"):
		return "debugger"
	case isInSet(name, "word", "excel", "winword.exe", "excel.exe", "libreoffice"):
		return "office"
	default:
		return "unknown"
	}
}

func isInSet(s string, set ...string) bool {
	for _, v := range set {
		if s == v {
			return true
		}
	}
	return false
}

func inferPrivilege(user string) string {
	switch user {
	case "root", "SYSTEM", "NT AUTHORITY\\SYSTEM":
		return "high"
	case "":
		return "low"
	default:
		return "medium"
	}
}

func parentRelationshipScore(ppid, pid int) float32 {
	switch {
	case ppid == 0 || ppid == 1:
		return 0.0
	case ppid == pid:
		return 1.0
	default:
		return 0.5
	}
}

func fileOperationSubtype(op string) string {
	switch op {
	case "create":
		return "file_create"
	case "write":
		return "file_write"
	case "delete":
		return "file_delete"
	case "rename":
		return "file_rename"
	default:
		return "file_read"
	}
}

func authSubtype(outcome string) string {
	switch outcome {
	case "logout":
		return "auth_logout"
	default:
		return "auth_login"
	}
}
