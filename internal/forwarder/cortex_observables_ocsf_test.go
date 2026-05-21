package forwarder

import (
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
	"github.com/razatechofficial/edr/pkg/ocsf"
)

func TestCortexObservablesFromOCSFOnly(t *testing.T) {
	env := ocsf.FromDetectionAlert(ocsf.AlertInput{
		AlertID:    "ocsf-cortex",
		FileSHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		DestIP:     "203.0.113.42",
		Domain:     "evil.example",
		URL:        "https://evil.example/payload.bin",
		Timestamp:  time.Now().UTC(),
	}, ocsf.DefaultProduct("test"))
	got := CortexObservables(schema.Alert{OCSF: ocsf.EnvelopeToMap(env)})
	if len(got["hash"]) != 1 {
		t.Fatalf("hash: %v", got["hash"])
	}
	if len(got["ip"]) == 0 || got["ip"][0] != "203.0.113.42" {
		t.Fatalf("ip: %v", got["ip"])
	}
	if len(got["domain"]) != 1 || got["domain"][0] != "evil.example" {
		t.Fatalf("domain: %v", got["domain"])
	}
}
