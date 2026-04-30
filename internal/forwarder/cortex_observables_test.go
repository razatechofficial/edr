package forwarder

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/schema"
)

func TestCortexObservablesGolden(t *testing.T) {
	alert := schema.Alert{
		SchemaVersion: "v1",
		AlertID:       "golden-1",
		RuleID:        "RULE-FUSION",
		EndpointID:    "endpoint-x",
		Severity:      schema.SeverityHigh,
		Timestamp:     time.Now().UTC(),
		FileSHA256:    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		DestIP:        "203.0.113.42",
		Domain:        "evil.example.",
		URL:           "https://evil.example/payload.bin",
	}
	got := CortexObservables(alert)
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}

	var round map[string][]string
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if len(round["hash"]) != 1 || round["hash"][0][:8] != "ba7816bf" {
		t.Fatalf("hash: %v", round["hash"])
	}
	wantIP := "203.0.113.42"
	if len(round["ip"]) == 0 || round["ip"][0] != wantIP {
		t.Fatalf("ip: %v", round["ip"])
	}
	if len(round["domain"]) != 1 || round["domain"][0] != "evil.example" {
		t.Fatalf("domain: %v", round["domain"])
	}
	if len(round["url"]) != 1 || round["url"][0] != alert.URL {
		t.Fatalf("url: %v", round["url"])
	}
}
