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
		Kind      string                         `json:"kind"`
		Process   *schema.ProcessEvent           `json:"process,omitempty"`
		Network   *schema.NetworkEvent           `json:"network,omitempty"`
		Auth      *schema.AuthEvent              `json:"auth,omitempty"`
		File      *schema.FileEvent              `json:"file,omitempty"`
		Fork      *schema.ForkEvent              `json:"fork,omitempty"`
		Registry  *schema.RegistryEvent          `json:"registry,omitempty"`
		Injection *schema.ProcessInjectionEvent `json:"injection,omitempty"`
	}{}
	switch {
	case t.Process != nil:
		w.Kind, w.Process = "process", t.Process
	case t.Network != nil:
		w.Kind, w.Network = "network", t.Network
	case t.Auth != nil:
		w.Kind, w.Auth = "auth", t.Auth
	case t.File != nil:
		w.Kind, w.File = "file", t.File
	case t.Fork != nil:
		w.Kind, w.Fork = "fork", t.Fork
	case t.Registry != nil:
		w.Kind, w.Registry = "registry", t.Registry
	case t.Injection != nil:
		w.Kind, w.Injection = "injection", t.Injection
	default:
		return nil, nil
	}
	return json.Marshal(w)
}
