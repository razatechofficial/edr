package collector

import (
	"encoding/json"
)

// MarshalTelemetryLine serializes one telemetry unit as an OCSF 1.3 JSON object.
func MarshalTelemetryLine(t *Telemetry) ([]byte, error) {
	if t == nil {
		return nil, nil
	}
	env := ocsfEnvelopeForTelemetry(t)
	if len(env) == 0 {
		return nil, nil
	}
	return json.Marshal(env)
}
