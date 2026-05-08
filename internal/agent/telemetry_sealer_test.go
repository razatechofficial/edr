package agent

import (
	"testing"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/telemetry"
)

func TestBuildTelemetryEnvelopeSealer_InvalidKeyMissing(t *testing.T) {
	var c config.Config
	c.Forwarder.SealEnvelopes = true
	c.Forwarder.SealKeyPath = ""
	fn, _, err := buildTelemetryEnvelopeSealer(c)
	if err == nil {
		t.Fatalf("expected error, got non-nil sealer callback")
	}
	if fn != nil {
		t.Fatal("unexpected sealer func")
	}
}

func TestApplyEnvelopeSealerToSender(t *testing.T) {
	var c config.Config
	c.Forwarder.SealEnvelopes = true
	c.Forwarder.SealKeyPath = "/nosuch/edr/key.bogus"
	c.Forwarder.SealKeyID = "k1"
	s := telemetry.NewSender(telemetry.NoopTransport{}, nil, telemetry.DefaultSenderConfig(), nil)
	if err := applyEnvelopeSealerToSender(s, c); err == nil {
		t.Fatal("expected error")
	}
}
