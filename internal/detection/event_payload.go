package detection

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/razatechofficial/edr/internal/detection/rules"
	"github.com/razatechofficial/edr/internal/schema"
)

// EventPayloadFromInterface maps a wire/raw event to a union pointer. Unstructured
// is used for map-shaped Sigma/IOC events and other untyped payloads.
func EventPayloadFromInterface(v interface{}) *EventPayload {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case *EventPayload:
		return x
	case EventPayload:
		return &x
	case *schema.ProcessEvent:
		return &EventPayload{Process: x}
	case *schema.FileEvent:
		return &EventPayload{File: x}
	case *schema.NetworkEvent:
		return &EventPayload{Network: x}
	case *schema.RegistryEvent:
		return &EventPayload{Registry: x}
	case *schema.AuthEvent:
		return &EventPayload{Auth: x}
	case *schema.ProcessInjectionEvent:
		return &EventPayload{Injection: x}
	case *schema.MemoryEvent:
		return &EventPayload{Memory: x}
	case *schema.CredentialAccessEvent:
		return &EventPayload{Credential: x}
	case *schema.ContainerEvent:
		return &EventPayload{Container: x}
	case *schema.PersistenceEvent:
		return &EventPayload{Persistence: x}
	case *schema.PrivacyEvent:
		return &EventPayload{Privacy: x}
	case *schema.TamperEvent:
		return &EventPayload{Tamper: x}
	case map[string]interface{}:
		return &EventPayload{Unstructured: x}
	default:
		if m := rules.EventToMap(v); m != nil {
			return &EventPayload{Unstructured: m}
		}
		return nil
	}
}

// rawEventFromPayload picks a single object for events.Alert.RawEvent.
func rawEventFromPayload(p *EventPayload) interface{} {
	if p == nil {
		return nil
	}
	switch {
	case p.Process != nil:
		return p.Process
	case p.File != nil:
		return p.File
	case p.Network != nil:
		return p.Network
	case p.Registry != nil:
		return p.Registry
	case p.Auth != nil:
		return p.Auth
	case p.Injection != nil:
		return p.Injection
	case p.Memory != nil:
		return p.Memory
	case p.Credential != nil:
		return p.Credential
	case p.Container != nil:
		return p.Container
	case p.Persistence != nil:
		return p.Persistence
	case p.Privacy != nil:
		return p.Privacy
	case p.Tamper != nil:
		return p.Tamper
	case p.Unstructured != nil:
		return p.Unstructured
	default:
		return nil
	}
}

func eventPayloadHost(p *EventPayload) string {
	if p == nil {
		return ""
	}
	if p.Unstructured != nil {
		return mapStringField(p.Unstructured, "hostname", "endpoint_id", "EndpointId")
	}
	// BaseEvent-style: many schema types embed BaseEvent with Hostname
	if p.Process != nil {
		return strings.TrimSpace(p.Process.Hostname)
	}
	if p.File != nil {
		return strings.TrimSpace(p.File.Hostname)
	}
	if p.Network != nil {
		return strings.TrimSpace(p.Network.Hostname)
	}
	if p.Registry != nil {
		return strings.TrimSpace(p.Registry.Hostname)
	}
	if p.Auth != nil {
		return strings.TrimSpace(p.Auth.Hostname)
	}
	if p.Injection != nil {
		return strings.TrimSpace(p.Injection.Hostname)
	}
	if p.Memory != nil {
		return strings.TrimSpace(p.Memory.Hostname)
	}
	if p.Credential != nil {
		return strings.TrimSpace(p.Credential.Hostname)
	}
	if p.Container != nil {
		return strings.TrimSpace(p.Container.Hostname)
	}
	if p.Persistence != nil {
		return strings.TrimSpace(p.Persistence.Hostname)
	}
	if p.Privacy != nil {
		return strings.TrimSpace(p.Privacy.Hostname)
	}
	if p.Tamper != nil {
		return strings.TrimSpace(p.Tamper.Hostname)
	}
	return ""
}

func eventPayloadPIDString(p *EventPayload) string {
	n := eventPayloadPIDInt(p)
	if n == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", n)
}

func eventPayloadPIDInt(p *EventPayload) int {
	if p == nil {
		return 0
	}
	if p.Unstructured != nil {
		return mapIntField(p.Unstructured, "pid", "PID", "actor_pid", "ActorPID")
	}
	if p.Process != nil {
		return p.Process.PID
	}
	if p.File != nil {
		return p.File.ActorPID
	}
	if p.Network != nil {
		return p.Network.PID
	}
	if p.Registry != nil {
		return p.Registry.ActorPID
	}
	if p.Injection != nil {
		return p.Injection.SourcePID
	}
	if p.Memory != nil {
		return int(p.Memory.TargetPID)
	}
	if p.Credential != nil {
		return int(p.Credential.SourcePID)
	}
	if p.Container != nil {
		return p.Container.PID
	}
	if p.Persistence != nil {
		return int(p.Persistence.PID)
	}
	if p.Privacy != nil {
		return int(p.Privacy.AccessingPID)
	}
	if p.Tamper != nil {
		return 0
	}
	if p.Auth != nil {
		return 0
	}
	return 0
}

func mapStringField(m map[string]interface{}, keys ...string) string {
	for _, want := range keys {
		for k, v := range m {
			if strings.EqualFold(k, want) {
				return strings.TrimSpace(fmt.Sprint(v))
			}
		}
	}
	return ""
}

func mapIntField(m map[string]interface{}, keys ...string) int {
	s := mapStringField(m, keys...)
	if s == "" {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}

// extractProcessNameForScoring returns a best-effort process name for known-good checks.
func extractProcessNameForScoring(p *EventPayload) string {
	if p == nil {
		return ""
	}
	if p.Unstructured != nil {
		img := mapStringField(p.Unstructured, "Image", "image", "process_name", "ProcessName", "process_path", "ProcessPath")
		if img != "" {
			return filepath.Base(img)
		}
		return mapStringField(p.Unstructured, "ImagePath", "path")
	}
	if p.Process != nil {
		if p.Process.ProcessName != "" {
			return filepath.Base(p.Process.ProcessName)
		}
		if p.Process.ProcessPath != "" {
			return filepath.Base(p.Process.ProcessPath)
		}
	}
	if p.File != nil && p.File.Path != "" {
		return filepath.Base(p.File.Path)
	}
	return ""
}
