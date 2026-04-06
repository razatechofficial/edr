package features

import (
	"math"
	"time"
)

const (
	numEventSubtypes = 25
	numProcessCats   = 8
	numPrivLevels    = 3

	// FeaturesPerEvent is the total encoded dimension for a single event:
	// event_type(25) + process_category(8) + privilege_level(3) +
	// network_flag(1) + file_write_flag(1) + registry_flag(1) +
	// time_of_day(1) + day_of_week(7) + parent_relationship_score(1) = 48
	FeaturesPerEvent = 48
)

var eventSubtypeIndex = map[string]int{
	"process_create":    0,
	"process_terminate": 1,
	"process_inject":    2,
	"file_create":       3,
	"file_write":        4,
	"file_delete":       5,
	"file_rename":       6,
	"file_read":         7,
	"network_connect":   8,
	"network_listen":    9,
	"network_send":      10,
	"network_receive":   11,
	"network_dns":       12,
	"registry_create":   13,
	"registry_write":    14,
	"registry_delete":   15,
	"registry_read":     16,
	"memory_alloc":      17,
	"memory_protect":    18,
	"auth_login":        19,
	"auth_logout":       20,
	"auth_privilege":    21,
	"module_load":       22,
	"mount_operation":   23,
	"ptrace_attach":     24,
}

var processCategoryIndex = map[string]int{
	"system":    0,
	"browser":   1,
	"office":    2,
	"shell":     3,
	"scripting": 4,
	"compiler":  5,
	"debugger":  6,
	"unknown":   7,
}

// OneHotEventType encodes an event subtype string into a one-hot vector of
// length numEventSubtypes, written into dst starting at offset.
func OneHotEventType(dst []float32, offset int, eventSubtype string) {
	if idx, ok := eventSubtypeIndex[eventSubtype]; ok && offset+idx < len(dst) {
		dst[offset+idx] = 1.0
	}
}

// OneHotProcessCategory encodes a process category into a one-hot vector of
// length numProcessCats, written into dst starting at offset.
func OneHotProcessCategory(dst []float32, offset int, category string) {
	idx, ok := processCategoryIndex[category]
	if !ok {
		idx = processCategoryIndex["unknown"]
	}
	if offset+idx < len(dst) {
		dst[offset+idx] = 1.0
	}
}

// EncodePrivilegeLevel writes a one-hot privilege encoding (low/medium/high)
// into dst at the given offset.
func EncodePrivilegeLevel(dst []float32, offset int, level string) {
	if offset+2 >= len(dst) {
		return
	}
	switch level {
	case "high":
		dst[offset+2] = 1.0
	case "medium":
		dst[offset+1] = 1.0
	default:
		dst[offset] = 1.0
	}
}

// NormalizeTimeOfDay converts a timestamp to a [0,1) value representing the
// fraction of the day elapsed.
func NormalizeTimeOfDay(t time.Time) float32 {
	seconds := t.Hour()*3600 + t.Minute()*60 + t.Second()
	return float32(seconds) / 86400.0
}

// EncodeDayOfWeek writes a 7-element one-hot vector for the day of the week
// into dst at the given offset (Sunday=0, Saturday=6).
func EncodeDayOfWeek(dst []float32, offset int, t time.Time) {
	day := int(t.Weekday())
	if offset+day < len(dst) {
		dst[offset+day] = 1.0
	}
}

// IsBusinessHours returns 1.0 if t falls within 08:00–18:00 on a weekday.
func IsBusinessHours(t time.Time) float32 {
	day := t.Weekday()
	if day == time.Saturday || day == time.Sunday {
		return 0.0
	}
	if h := t.Hour(); h >= 8 && h < 18 {
		return 1.0
	}
	return 0.0
}

// IsWeekend returns 1.0 if t falls on Saturday or Sunday.
func IsWeekend(t time.Time) float32 {
	if day := t.Weekday(); day == time.Saturday || day == time.Sunday {
		return 1.0
	}
	return 0.0
}

// LogScale returns log1p(x), clamped to 0 for non-positive input.
func LogScale(x float64) float32 {
	if x <= 0 {
		return 0
	}
	return float32(math.Log1p(x))
}

// NormalizeMinMax scales v into [0,1] given known min and max bounds.
func NormalizeMinMax(v, lo, hi float64) float32 {
	if hi <= lo {
		return 0
	}
	n := (v - lo) / (hi - lo)
	return float32(max(0, min(1, n)))
}
