package detection

import (
	"context"
	"time"
)

// DetectionEngineAPI is the event-stream oriented detection interface.
// It layers on top of the existing Engine implementation without replacing it.
type DetectionEngineAPI interface {
	Process(ctx context.Context, event interface{}) []Detection
	Reload() error
	Stats() EngineStats
}

type Detection struct {
	ID                 string
	Timestamp          time.Time
	RuleID             string
	RuleName           string
	Severity           Severity
	Confidence         float64
	TechniqueID        string
	TacticName         string
	Source             DetectionSource
	Event              interface{}
	Context            []interface{}
	Tags               []string
	Description        string
	Remediation        string
	FalsePositiveScore float64
}

type Severity int

const (
	P0 Severity = iota
	P1
	P2
	P3
)

type DetectionSource int

const (
	SourceSigma DetectionSource = iota
	SourceYARA
	SourceBehavioral
	SourceML
)

type EngineStats struct {
	EventsProcessed   uint64
	DetectionsEmitted uint64
	RulesLoaded       RuleCount
	ProcessingLatency time.Duration
	DroppedEvents     uint64
}

type RuleCount struct {
	Sigma      int
	YARA       int
	Behavioral int
}
