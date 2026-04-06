package telemetry

import (
	"fmt"
	"os"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/events"
)

// NormalizedEvent is the canonical telemetry representation shared across the
// entire pipeline. Every raw event type is mapped to this structure before
// enrichment, batching, and shipping.
type NormalizedEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	EventType   string            `json:"event_type"`
	AgentID     string            `json:"agent_id"`
	Hostname    string            `json:"hostname"`
	OS          string            `json:"os"`
	PID         int               `json:"pid,omitempty"`
	PPID        int               `json:"ppid,omitempty"`
	ProcessName string            `json:"process_name,omitempty"`
	ProcessPath string            `json:"process_path,omitempty"`
	CommandLine string            `json:"command_line,omitempty"`
	User        string            `json:"user,omitempty"`
	Hashes      []string          `json:"hashes,omitempty"`
	SourceIP    string            `json:"source_ip,omitempty"`
	SourcePort  int               `json:"source_port,omitempty"`
	DestIP      string            `json:"dest_ip,omitempty"`
	DestPort    int               `json:"dest_port,omitempty"`
	Protocol    string            `json:"protocol,omitempty"`
	Domain      string            `json:"domain,omitempty"`
	FilePath    string            `json:"file_path,omitempty"`
	FileOp      string            `json:"file_op,omitempty"`
	FileHash    string            `json:"file_hash,omitempty"`
	AuthType    string            `json:"auth_type,omitempty"`
	AuthOutcome string            `json:"auth_outcome,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	AlertID     string            `json:"alert_id,omitempty"`
	RuleID      string            `json:"rule_id,omitempty"`
	Title       string            `json:"title,omitempty"`
	Description string            `json:"description,omitempty"`
	Score       int               `json:"score,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	MITRE       []events.MITREAttack `json:"mitre,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
	Critical    bool              `json:"critical,omitempty"`

	// Enrichment fields populated by Enricher.
	ParentChain   []string `json:"parent_chain,omitempty"`
	GeoCountry    string   `json:"geo_country,omitempty"`
	GeoCity       string   `json:"geo_city,omitempty"`
	ASN           string   `json:"asn,omitempty"`
	ASOrg         string   `json:"as_org,omitempty"`
	ThreatTags    []string `json:"threat_tags,omitempty"`
	ResolvedUser  string   `json:"resolved_user,omitempty"`
	ResolvedGroup string   `json:"resolved_group,omitempty"`
}

// Normalizer converts heterogeneous event types into NormalizedEvent.
type Normalizer struct {
	agentID  string
	hostname string
}

// NewNormalizer creates a Normalizer pre-configured with agent identity.
func NewNormalizer(agentID string) *Normalizer {
	hostname, _ := os.Hostname()
	return &Normalizer{
		agentID:  agentID,
		hostname: hostname,
	}
}

// Normalize maps any supported event type to the canonical NormalizedEvent.
// Returns an error for unrecognised types.
func (n *Normalizer) Normalize(event interface{}) (*NormalizedEvent, error) {
	ne := &NormalizedEvent{
		AgentID:  n.agentID,
		Hostname: n.hostname,
	}

	switch ev := event.(type) {
	case *schema.ProcessEvent:
		n.normalizeProcess(ne, ev)
	case schema.ProcessEvent:
		n.normalizeProcess(ne, &ev)
	case *schema.NetworkEvent:
		n.normalizeNetwork(ne, ev)
	case schema.NetworkEvent:
		n.normalizeNetwork(ne, &ev)
	case *schema.FileEvent:
		n.normalizeFile(ne, ev)
	case schema.FileEvent:
		n.normalizeFile(ne, &ev)
	case *schema.AuthEvent:
		n.normalizeAuth(ne, ev)
	case schema.AuthEvent:
		n.normalizeAuth(ne, &ev)
	case *events.Alert:
		n.normalizeAlert(ne, ev)
	case events.Alert:
		n.normalizeAlert(ne, &ev)
	case *schema.Alert:
		n.normalizeSchemaAlert(ne, ev)
	case schema.Alert:
		n.normalizeSchemaAlert(ne, &ev)
	default:
		return nil, fmt.Errorf("normalizer: unsupported event type %T", event)
	}

	if ne.Hostname == "" {
		ne.Hostname = n.hostname
	}
	if ne.Timestamp.IsZero() {
		ne.Timestamp = time.Now().UTC()
	}
	return ne, nil
}

func (n *Normalizer) normalizeProcess(ne *NormalizedEvent, ev *schema.ProcessEvent) {
	ne.Timestamp = ev.Timestamp
	ne.EventType = string(schema.EventProcess)
	ne.Hostname = ev.Hostname
	ne.OS = ev.OS
	ne.PID = ev.PID
	ne.PPID = ev.PPID
	ne.ProcessName = ev.ProcessName
	ne.ProcessPath = ev.ProcessPath
	ne.CommandLine = ev.CommandLine
	ne.User = ev.User
	ne.Hashes = ev.Hashes
}

func (n *Normalizer) normalizeNetwork(ne *NormalizedEvent, ev *schema.NetworkEvent) {
	ne.Timestamp = ev.Timestamp
	ne.EventType = string(schema.EventNetwork)
	ne.Hostname = ev.Hostname
	ne.OS = ev.OS
	ne.PID = ev.PID
	ne.Protocol = ev.Protocol
	ne.SourceIP = ev.SourceIP
	ne.SourcePort = ev.SourcePt
	ne.DestIP = ev.DestIP
	ne.DestPort = ev.DestPt
	ne.Domain = ev.Domain
}

func (n *Normalizer) normalizeFile(ne *NormalizedEvent, ev *schema.FileEvent) {
	ne.Timestamp = ev.Timestamp
	ne.EventType = string(schema.EventFile)
	ne.Hostname = ev.Hostname
	ne.OS = ev.OS
	ne.PID = ev.ActorPID
	ne.FilePath = ev.Path
	ne.FileOp = ev.Operation
	ne.FileHash = ev.Hash
}

func (n *Normalizer) normalizeAuth(ne *NormalizedEvent, ev *schema.AuthEvent) {
	ne.Timestamp = ev.Timestamp
	ne.EventType = string(schema.EventAuth)
	ne.Hostname = ev.Hostname
	ne.OS = ev.OS
	ne.User = ev.User
	ne.AuthOutcome = ev.Outcome
	ne.AuthType = ev.AuthType
	ne.SourceIP = ev.SourceIP
	ne.SessionID = ev.SessionID
}

func (n *Normalizer) normalizeAlert(ne *NormalizedEvent, ev *events.Alert) {
	ne.Timestamp = ev.Timestamp
	ne.EventType = "alert"
	ne.AlertID = ev.ID
	ne.RuleID = ev.RuleID
	ne.Severity = string(ev.Severity)
	ne.Title = ev.Title
	ne.Description = ev.Description
	ne.Tags = ev.Tags
	ne.MITRE = ev.MITRE
	if ev.Severity == events.SeverityCritical || ev.Severity == events.SeverityHigh {
		ne.Critical = true
	}
}

func (n *Normalizer) normalizeSchemaAlert(ne *NormalizedEvent, ev *schema.Alert) {
	ne.Timestamp = ev.Timestamp
	ne.EventType = "alert"
	ne.AlertID = ev.AlertID
	ne.RuleID = ev.RuleID
	ne.Severity = string(ev.Severity)
	ne.Title = ev.Title
	ne.Description = ev.Description
	ne.Score = ev.Score
	ne.PID = ev.ProcessPID
	ne.ProcessName = ev.ProcessName
	ne.ProcessPath = ev.ProcessPath
	ne.CommandLine = ev.CommandLine
	if ev.Severity == schema.SeverityCritical || ev.Severity == schema.SeverityHigh {
		ne.Critical = true
	}
}
