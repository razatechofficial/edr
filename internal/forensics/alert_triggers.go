package forensics

import (
	"context"
	"time"

	"go.uber.org/zap"
)

const defaultAlertArtifactTimeout = 2 * time.Minute

// AlertTriggerMeta is minimal context forwarded from detection/response when an
// artifact pass is queued (WHIDS-class alert-driven IR).
// The field names are tagged because this struct is serialised into every
// stored bundle, where it is the evidence's only statement of which detection
// produced it. A tool reading the bundle later — including this agent's own
// shipper — matches on these names.
type AlertTriggerMeta struct {
	AlertID    string `json:"alert_id"`
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity,omitempty"`
	EndpointID string `json:"endpoint_id,omitempty"`
}

// CollectArtifactsForAlert performs a bounded version of CollectAll intended for
// alert-triggered playbooks. It is not registered in collector defaults — callers
// (response/IR) opt in explicitly.
func CollectArtifactsForAlert(ctx context.Context, log *zap.Logger, meta AlertTriggerMeta, deep *ForensicsDeepConfig) (*ArtifactBundle, error) {
	if log == nil {
		log = zap.NewNop()
	}
	_ = meta // Reserved for prioritization / tagging of bundle categories.
	ctx, cancel := context.WithTimeout(ctx, defaultAlertArtifactTimeout)
	defer cancel()
	return NewArtifactCollector(log, deep).CollectAll(ctx)
}
