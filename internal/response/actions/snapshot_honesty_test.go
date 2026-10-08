package actions

import (
	"context"
	"errors"
	"testing"
)

// These paths used to return nil, reporting success for a snapshot that was
// never created. A responder reading that result would believe a disk image
// existed and could be returned to — and would only discover otherwise at the
// moment they needed it.
func TestUnimplementedCloudSnapshotsReportFailure(t *testing.T) {
	a := &SnapshotAction{Reason: "test"}
	ctx := context.Background()

	for name, fn := range map[string]func(context.Context) error{
		"aws":   a.createAWSSnapshot,
		"azure": a.createAzureSnapshot,
		"gcp":   a.createGCPSnapshot,
	} {
		err := fn(ctx)
		if err == nil {
			t.Errorf("%s reported success for a snapshot it cannot take", name)
			continue
		}
		if !errors.Is(err, errSnapshotUnavailable) {
			t.Errorf("%s: err = %v; want it to wrap errSnapshotUnavailable so callers can tell why", name, err)
		}
	}
}

// The error has to say what is missing, or an operator cannot act on it.
func TestTheFailureNamesWhatIsMissing(t *testing.T) {
	err := (&SnapshotAction{}).createAWSSnapshot(context.Background())
	if err == nil {
		t.Fatal("no error")
	}
	if got := err.Error(); got == "" || !errors.Is(err, errSnapshotUnavailable) {
		t.Fatalf("err = %q", got)
	}
}
