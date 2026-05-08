package agent

import (
	"fmt"
	"strings"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/telemetry"
	"github.com/razatechofficial/edr/internal/transport"
)

// buildTelemetryEnvelopeSealer returns AES-GCM sealer when seal_envelopes is true.
func buildTelemetryEnvelopeSealer(cfg config.Config) (fn func([]byte) ([]byte, error), required bool, err error) {
	if !cfg.Forwarder.SealEnvelopes {
		return nil, false, nil
	}
	if strings.TrimSpace(cfg.Forwarder.SealKeyPath) == "" {
		return nil, true, fmt.Errorf("forwarder.seal_key_path is required when seal_envelopes is true")
	}
	f, e := transport.AESGCMSealer(cfg.Forwarder.SealKeyPath, cfg.Forwarder.SealKeyID)
	return f, true, e
}

// applyEnvelopeSealerToSender configures telemetry.Sender with the same sealing policy as the forwarder relay.
func applyEnvelopeSealerToSender(sender *telemetry.Sender, cfg config.Config) error {
	sender.SetSealRequired(cfg.Forwarder.SealEnvelopes)
	sealFn, _, err := buildTelemetryEnvelopeSealer(cfg)
	if err != nil {
		return fmt.Errorf("telemetry sealer: %w", err)
	}
	if sealFn != nil {
		sender.SetSealer(sealFn)
	}
	return nil
}
