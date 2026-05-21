package collector

import (
	"encoding/json"

	"github.com/razatechofficial/edr/internal/schema"
)

// MarshalTelemetryLine serializes one telemetry unit as a single JSON object for forwarding.
func MarshalTelemetryLine(t *Telemetry) ([]byte, error) {
	if t == nil {
		return nil, nil
	}
	w := struct {
		Kind           string                             `json:"kind"`
		OCSF           map[string]any                     `json:"ocsf,omitempty"`
		Process        *schema.ProcessEvent               `json:"process,omitempty"`
		Network       *schema.NetworkEvent          `json:"network,omitempty"`
		Auth          *schema.AuthEvent             `json:"auth,omitempty"`
		Task          *schema.TaskEvent             `json:"task,omitempty"`
		Service       *schema.ServiceEvent          `json:"service,omitempty"`
		Credential    *schema.CredentialAccessEvent `json:"credential,omitempty"`
		Memory        *schema.MemoryEvent           `json:"memory,omitempty"`
		Container     *schema.ContainerEvent        `json:"container,omitempty"`
		SecPolicy     *schema.SecurityPolicyEvent   `json:"security_policy,omitempty"`
		Tamper        *schema.TamperEvent           `json:"tamper,omitempty"`
		Persistence   *schema.PersistenceEvent      `json:"persistence,omitempty"`
		Privacy       *schema.PrivacyEvent          `json:"privacy,omitempty"`
		Gatekeeper    *schema.GatekeeperBypassEvent `json:"gatekeeper,omitempty"`
		Dropped       *schema.DroppedEventsEvent    `json:"dropped_events,omitempty"`
		TIStatus      *schema.TIStatusEvent         `json:"ti_status,omitempty"`
		FeatureStatus *schema.FeatureStatusEvent    `json:"feature_status,omitempty"`
		File          *schema.FileEvent             `json:"file,omitempty"`
		Fork          *schema.ForkEvent             `json:"fork,omitempty"`
		Registry      *schema.RegistryEvent         `json:"registry,omitempty"`
		Injection     *schema.ProcessInjectionEvent `json:"injection,omitempty"`
		Compliance    *schema.ComplianceFindingEvent `json:"compliance,omitempty"`
		ComplianceScan *schema.ComplianceScanSummaryEvent `json:"compliance_scan,omitempty"`
		Privilege      *schema.PrivilegeEvent             `json:"privilege,omitempty"`
	}{}
	switch {
	case t.Process != nil:
		w.Kind, w.Process = "process", t.Process
	case t.Network != nil:
		w.Kind, w.Network = "network", t.Network
	case t.Auth != nil:
		w.Kind, w.Auth = "auth", t.Auth
	case t.Task != nil:
		w.Kind, w.Task = "task", t.Task
	case t.Service != nil:
		w.Kind, w.Service = "service", t.Service
	case t.Credential != nil:
		w.Kind, w.Credential = "credential_access", t.Credential
	case t.Memory != nil:
		w.Kind, w.Memory = "memory", t.Memory
	case t.Container != nil:
		w.Kind, w.Container = "container", t.Container
	case t.SecPolicy != nil:
		w.Kind, w.SecPolicy = "security_policy", t.SecPolicy
	case t.Tamper != nil:
		w.Kind, w.Tamper = "tamper", t.Tamper
	case t.Persistence != nil:
		w.Kind, w.Persistence = "persistence", t.Persistence
	case t.Privacy != nil:
		w.Kind, w.Privacy = "privacy", t.Privacy
	case t.Gatekeeper != nil:
		w.Kind, w.Gatekeeper = "gatekeeper_bypass", t.Gatekeeper
	case t.Dropped != nil:
		w.Kind, w.Dropped = "dropped_events", t.Dropped
	case t.TIStatus != nil:
		w.Kind, w.TIStatus = "ti_status", t.TIStatus
	case t.FeatureStatus != nil:
		w.Kind, w.FeatureStatus = "feature_status", t.FeatureStatus
	case t.File != nil:
		w.Kind, w.File = "file", t.File
	case t.Fork != nil:
		w.Kind, w.Fork = "fork", t.Fork
	case t.Registry != nil:
		w.Kind, w.Registry = "registry", t.Registry
	case t.Injection != nil:
		w.Kind, w.Injection = "injection", t.Injection
	case t.Compliance != nil:
		w.Kind, w.Compliance = "compliance_finding", t.Compliance
	case t.ComplianceScan != nil:
		w.Kind, w.ComplianceScan = "compliance_scan", t.ComplianceScan
	case t.Privilege != nil:
		w.Kind, w.Privilege = "privilege", t.Privilege
	default:
		return nil, nil
	}
	w.OCSF = ocsfEnvelopeForTelemetry(t)
	return json.Marshal(w)
}
