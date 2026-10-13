package forensics

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// RFC 3227 requires collection in order of volatility: the state that
// disappears fastest is captured first, because anything slower taken ahead of
// it destroys it. The filesystem scan used to run second, before sockets were
// read, so a connection that had already closed was the normal case.
func TestStagesRunInOrderOfVolatility(t *testing.T) {
	ac := NewArtifactCollector(zap.NewNop(), nil)
	got := make([]string, 0, 5)
	for _, st := range ac.stages() {
		got = append(got, st.name)
		if st.why == "" {
			t.Errorf("stage %q does not record why it sits where it does", st.name)
		}
	}
	want := []string{"network", "process", "auth", "system", "file"}
	if len(got) != len(want) {
		t.Fatalf("stages %v, expected %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stage order %v, expected %v", got, want)
		}
	}
}

func TestNetworkIsCollectedBeforeTheFilesystem(t *testing.T) {
	// The specific inversion that was there: the disk scan can take seconds,
	// and a socket does not survive it.
	ac := NewArtifactCollector(zap.NewNop(), nil)
	netAt, fileAt := -1, -1
	for i, st := range ac.stages() {
		switch st.name {
		case "network":
			netAt = i
		case "file":
			fileAt = i
		}
	}
	if netAt < 0 || fileAt < 0 {
		t.Fatal("the network or file stage is missing")
	}
	if netAt > fileAt {
		t.Fatalf("network runs at %d, after the filesystem at %d", netAt, fileAt)
	}
}

func TestCollectAllRecordsWhatItDidAndWhen(t *testing.T) {
	ac := NewArtifactCollector(zap.NewNop(), nil)
	bundle, err := ac.CollectAll(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// Artifacts inside one bundle are not simultaneous, and a bundle that
	// cannot say when each part was read cannot support a timeline.
	if bundle.CompletedAt.Before(bundle.Timestamp) {
		t.Fatalf("completed %v before it started %v", bundle.CompletedAt, bundle.Timestamp)
	}
	want := []string{"network", "process", "auth", "system", "file"}
	if len(bundle.CollectionOrder) != len(want) {
		t.Fatalf("order %v", bundle.CollectionOrder)
	}
	for i := range want {
		if bundle.CollectionOrder[i] != want[i] {
			t.Fatalf("order %v, expected %v", bundle.CollectionOrder, want)
		}
	}
	if len(bundle.Timings) != len(want) {
		t.Fatalf("%d timings, expected %d", len(bundle.Timings), len(want))
	}
	for _, timing := range bundle.Timings {
		if timing.StartedAt.IsZero() {
			t.Errorf("stage %q has no start time", timing.Stage)
		}
	}
	// Each stage starts no earlier than the one before it finished, which is
	// what makes the order a fact about the evidence rather than a claim.
	for i := 1; i < len(bundle.Timings); i++ {
		prev := bundle.Timings[i-1]
		if bundle.Timings[i].StartedAt.Before(prev.StartedAt) {
			t.Errorf("stage %q started before %q", bundle.Timings[i].Stage, prev.Stage)
		}
	}
}

func TestCollectAllStopsCleanlyOnACancelledContext(t *testing.T) {
	ac := NewArtifactCollector(zap.NewNop(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	bundle, err := ac.CollectAll(ctx)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// Every stage reports that it was not collected, rather than the whole
	// collection failing with nothing to show.
	if len(bundle.Errors) != 5 {
		t.Fatalf("%d errors, expected one per stage: %v", len(bundle.Errors), bundle.Errors)
	}
}

func TestFileArtifactsCarryRecordsAndSayWhatBoundedTheScan(t *testing.T) {
	ac := NewArtifactCollector(zap.NewNop(), nil)
	fa := ac.collectFileArtifacts(context.Background())
	if fa == nil {
		t.Fatal("no file artifacts")
	}
	// A short list must not be mistaken for a quiet host.
	if fa.ScanNote == "" {
		t.Fatal("the scan did not say what bounded it")
	}
	// The path lists stay in step with the records, so anything already
	// reading this bundle keeps working.
	if len(fa.TempFiles) != len(fa.TempRecords) {
		t.Fatalf("%d temp paths against %d records", len(fa.TempFiles), len(fa.TempRecords))
	}
	for i, rec := range fa.TempRecords {
		if fa.TempFiles[i] != rec.Path {
			t.Fatalf("path %d is %q but the record says %q", i, fa.TempFiles[i], rec.Path)
		}
	}
}
