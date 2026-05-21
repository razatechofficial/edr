package ocsf

import (
	"encoding/json"
	"time"
)

// EnvelopeToMap serializes an OCSF envelope to a generic JSON map for forwarding.
func EnvelopeToMap(e Envelope) map[string]any {
	b, err := json.Marshal(e)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

// NetworkInput is a neutral network flow snapshot for OCSF mapping.
type NetworkInput struct {
	EndpointID string
	Hostname   string
	OS         string
	Timestamp  int64 // unix ms; 0 = now
	PID        int
	Protocol   string
	SourceIP   string
	SourcePort int
	DestIP     string
	DestPort   int
	Domain     string
	Transport  string
}

// AuthInput is a neutral authentication snapshot for OCSF mapping.
type AuthInput struct {
	EndpointID string
	Hostname   string
	OS         string
	Timestamp  int64
	User       string
	Outcome    string
	AuthType   string
	SourceIP   string
	Success    bool
	Message    string
	Subsystem  string
}

// FromNetwork maps network telemetry to an OCSF Network Activity envelope.
func FromNetwork(in NetworkInput, product Product) Envelope {
	ts := in.Timestamp
	if ts == 0 {
		ts = timeNowMillis()
	}
	env := Envelope{
		ClassUID:     ClassUIDNetworkActivity,
		ClassName:    ClassNetworkActivity,
		CategoryUID:  4,
		CategoryName: "Network Activity",
		ActivityID:   1,
		ActivityName: "Open",
		Time:         ts,
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: product,
		},
		Unmapped: map[string]any{
			"endpoint_id": in.EndpointID,
			"hostname":    in.Hostname,
			"os":          in.OS,
			"pid":         in.PID,
			"protocol":    in.Protocol,
			"domain":      in.Domain,
			"transport":   in.Transport,
		},
	}
	if in.SourceIP != "" || in.SourcePort != 0 {
		env.SrcEndpoint = &Endpoint{IP: in.SourceIP, Port: in.SourcePort}
	}
	if in.DestIP != "" || in.DestPort != 0 {
		env.DstEndpoint = &Endpoint{IP: in.DestIP, Port: in.DestPort}
	}
	return env
}

// FromAuth maps authentication telemetry to an OCSF Authentication envelope.
func FromAuth(in AuthInput, product Product) Envelope {
	ts := in.Timestamp
	if ts == 0 {
		ts = timeNowMillis()
	}
	status, statusID := authStatus(in.Success, in.Outcome)
	env := Envelope{
		ClassUID:     ClassUIDAuthentication,
		ClassName:    ClassAuthentication,
		CategoryUID:  3,
		CategoryName: "Identity & Access Management",
		ActivityID:   1,
		ActivityName: in.AuthType,
		Time:         ts,
		Status:       status,
		StatusID:     statusID,
		Metadata: Metadata{
			Version:     SchemaVersion,
			Product:     product,
			LogProvider: in.Subsystem,
		},
		Unmapped: map[string]any{
			"endpoint_id": in.EndpointID,
			"hostname":    in.Hostname,
			"os":          in.OS,
			"auth_type":   in.AuthType,
			"outcome":     in.Outcome,
			"message":     in.Message,
		},
	}
	if in.User != "" {
		env.User = &UserRecord{Name: in.User, UID: in.User}
	}
	if in.SourceIP != "" {
		env.SrcEndpoint = &Endpoint{IP: in.SourceIP}
	}
	return env
}

// ForkInput is a process fork/clone snapshot for OCSF mapping.
type ForkInput struct {
	EndpointID string
	Hostname   string
	OS         string
	Timestamp  int64
	ParentPID  int
	ChildPID   int
	CloneFlags uint64
}

// RegistryInput is a registry operation snapshot for OCSF mapping.
type RegistryInput struct {
	EndpointID string
	Hostname   string
	OS         string
	Timestamp  int64
	KeyPath    string
	ValueName  string
	Operation  string
	ActorPID   int
}

// InjectionInput is a process injection snapshot for OCSF mapping.
type InjectionInput struct {
	EndpointID  string
	Hostname    string
	OS          string
	Timestamp   int64
	SourcePID   int
	TargetPID   int
	TargetImage string
	Technique   string
}

// FromFork maps fork telemetry to OCSF Process Activity (Launch).
func FromFork(in ForkInput, product Product) Envelope {
	ts := in.Timestamp
	if ts == 0 {
		ts = timeNowMillis()
	}
	return Envelope{
		ClassUID:     ClassUIDProcessActivity,
		ClassName:    ClassProcessActivity,
		CategoryUID:  1,
		CategoryName: "System Activity",
		ActivityID:   1,
		ActivityName: "Launch",
		Time:         ts,
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: product,
		},
		Process: &Process{
			PID:       in.ChildPID,
			ParentPID: in.ParentPID,
		},
		Unmapped: map[string]any{
			"endpoint_id": in.EndpointID,
			"hostname":    in.Hostname,
			"os":          in.OS,
			"clone_flags": in.CloneFlags,
			"fork":        true,
		},
	}
}

// FromRegistry maps registry telemetry to OCSF Registry Key Activity.
func FromRegistry(in RegistryInput, product Product) Envelope {
	ts := in.Timestamp
	if ts == 0 {
		ts = timeNowMillis()
	}
	path := in.KeyPath
	if in.ValueName != "" {
		path = path + `\` + in.ValueName
	}
	return Envelope{
		ClassUID:     ClassUIDRegistryKeyActivity,
		ClassName:    ClassRegistryKeyActivity,
		CategoryUID:  1,
		CategoryName: "System Activity",
		ActivityID:   1,
		ActivityName: in.Operation,
		Time:         ts,
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: product,
		},
		RegKey: &RegKey{Path: path},
		Unmapped: map[string]any{
			"endpoint_id": in.EndpointID,
			"hostname":    in.Hostname,
			"os":          in.OS,
			"actor_pid":   in.ActorPID,
			"operation":   in.Operation,
		},
	}
}

// FromInjection maps injection telemetry to OCSF Process Activity.
func FromInjection(in InjectionInput, product Product) Envelope {
	ts := in.Timestamp
	if ts == 0 {
		ts = timeNowMillis()
	}
	return Envelope{
		ClassUID:     ClassUIDProcessActivity,
		ClassName:    ClassProcessActivity,
		CategoryUID:  1,
		CategoryName: "System Activity",
		ActivityID:   2,
		ActivityName: "Inject",
		Time:         ts,
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: product,
		},
		Process: &Process{
			PID:  in.TargetPID,
			Path: in.TargetImage,
		},
		Unmapped: map[string]any{
			"endpoint_id":  in.EndpointID,
			"hostname":     in.Hostname,
			"os":           in.OS,
			"source_pid":   in.SourcePID,
			"technique":    in.Technique,
			"injection":    true,
		},
	}
}

// AnnotatedProcessInput maps non-process telemetry to Process Activity with labels.
type AnnotatedProcessInput struct {
	ProcessInput
	ActivityKind string
	Extra        map[string]any
}

// FromAnnotatedProcess wraps FromProcess with activity_kind metadata in unmapped.
func FromAnnotatedProcess(in AnnotatedProcessInput, product Product) Envelope {
	env := FromProcess(in.ProcessInput, product)
	if env.Unmapped == nil {
		env.Unmapped = map[string]any{}
	}
	if in.ActivityKind != "" {
		env.Unmapped["activity_kind"] = in.ActivityKind
	}
	for k, v := range in.Extra {
		env.Unmapped[k] = v
	}
	return env
}

func authStatus(success bool, outcome string) (string, int) {
	if success {
		return "Success", 1
	}
	if outcome != "" {
		return outcome, 2
	}
	return "Failure", 2
}

func timeNowMillis() int64 {
	return time.Now().UTC().UnixMilli()
}
