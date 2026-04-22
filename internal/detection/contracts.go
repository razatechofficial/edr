package detection

import (
	"context"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

// DetectionEngineAPI is the event-stream oriented detection interface.
// It layers on top of the existing Engine implementation without replacing it.
type DetectionEngineAPI interface {
	Process(ctx context.Context, event interface{}) []Detection
	Reload() error
	Stats() EngineStats
}

// EventPayload is a union of strong schema event pointers. At most one non-
// Unstructured field should be set. Unstructured holds map-shaped events
// (e.g. Sigma) when a typed form is not available.
type EventPayload struct {
	Process      *schema.ProcessEvent
	File         *schema.FileEvent
	Network      *schema.NetworkEvent
	Registry     *schema.RegistryEvent
	Auth         *schema.AuthEvent
	Injection    *schema.ProcessInjectionEvent
	Memory       *schema.MemoryEvent
	Credential   *schema.CredentialAccessEvent
	Container    *schema.ContainerEvent
	Persistence  *schema.PersistenceEvent
	Privacy      *schema.PrivacyEvent
	Tamper       *schema.TamperEvent
	Unstructured map[string]interface{}
}

type Detection struct {
	ID                 string
	Timestamp          time.Time
	RuleID             string
	RuleName           string
	Severity           Severity
	Confidence         float64
	BaseScore          float64
	Score              float64
	TechniqueID        string
	TacticName         string
	Source             DetectionSource
	Event              *EventPayload
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
	SourceDedup
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
