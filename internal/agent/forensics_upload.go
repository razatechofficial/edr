package agent

import (
	"context"
	"errors"

	"github.com/razatechofficial/edr/internal/forensics"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

// platformUploader adapts the XDR forensics client to the shipper's port.
//
// The adapter exists so internal/forensics states what it needs from a platform
// and nothing about how to reach one: the collection and retention logic is
// then testable without a server, and a second transport would not require
// changing it.
type platformUploader struct {
	client *xdrclient.ForensicsClient
}

func (p platformUploader) Upload(ctx context.Context, up forensics.Upload) (forensics.Outcome, error) {
	out, err := p.client.Upload(ctx, xdrclient.Bundle{
		Path:        up.Path,
		UID:         up.UID,
		AlertUID:    up.AlertUID,
		RuleUID:     up.RuleUID,
		Kind:        up.Kind,
		ContentType: up.ContentType,
		CollectedAt: up.CollectedAt,
	})
	if err != nil {
		// Translated rather than wrapped through, so the shipper's decision to
		// stop asking does not depend on which transport reported it.
		if errors.Is(err, xdrclient.ErrForensicsUnsupported) {
			return forensics.Outcome{}, errors.Join(forensics.ErrUnsupported, err)
		}
		return forensics.Outcome{}, err
	}
	return forensics.Outcome{
		Stored:      out.Stored,
		BytesStored: out.BytesStored,
		StorageRef:  out.StorageRef,
		Message:     out.Message,
	}, nil
}
