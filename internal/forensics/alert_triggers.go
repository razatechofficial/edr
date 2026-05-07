package forensics

import (
	"context"
	"time"

	"go.uber.org/zap"
)

const defaultAlertArtifactTimeout = 2 * time.Minute

// AlertTriggerMeta is minimal context forwarded from detection/response when an
// artifact pass is queued (WHIDS-class alert-driven IR).
type AlertTriggerMeta struct {
	AlertID    string
	RuleID     string
	Severity   string
	EndpointID string
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
