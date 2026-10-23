package kernel

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func livenessReport(t *testing.T, observe bool) CapabilityReport {
	t.Helper()
	tracker := newCapabilityTracker()
	tracker.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	if observe {
		tracker.observe(CapProcessExec)
	}
	return buildCapabilityReport(
		"ebpf", true, 42.5,
		map[CapabilityCategory]capabilityMechanism{
			CapProcessExec: {Mechanism: "ebpf_tracepoint", Attachments: []string{"hook_a"}},
		},
		map[string]bool{"hook_a": true},
		DerivationRuntimeAttach,
		tracker,
		"not built",
	)
}

func row(t *testing.T, rep CapabilityReport, cat CapabilityCategory) CapabilityStatus {
	t.Helper()
	for _, c := range rep.Categories {
		if c.Category == cat {
			return c
		}
	}
	t.Fatalf("category %q missing from report", cat)
	return CapabilityStatus{}
}

// The defect this field exists for: a successful attach call is not evidence
// that the hook is doing work. Measured on kernel 7.0.0-1017-azure, where a
// program the kernel had invoked zero times sat alongside a sibling in the
// same object invoked 5863 times.
func TestAttachedWithoutEvidenceIsNotLive(t *testing.T) {
	got := row(t, livenessReport(t, false), CapProcessExec)

	if !got.Attached {
		t.Fatal("precondition: the row should be attached")
	}
	if got.Live {
		t.Error("a row with no liveness evidence reported Live")
	}
	if got.LiveEvidence != "" {
		t.Errorf("LiveEvidence = %q with Live false", got.LiveEvidence)
	}
	// The row must say so, rather than leaving an operator to infer it from
	// a combination of booleans.
	if !strings.Contains(got.Reason, "not confirmed working") {
		t.Errorf("Reason = %q, want it to say the hook is unconfirmed", got.Reason)
	}
}

// An event reaching userspace proves the whole path, so it is the strongest
// evidence and must retract the unconfirmed note.
func TestObservedEventMakesARowLive(t *testing.T) {
	got := row(t, livenessReport(t, true), CapProcessExec)

	if !got.Live {
		t.Fatal("a producing row did not report Live")
	}
	if got.LiveEvidence != LiveEvidenceEvent {
		t.Errorf("LiveEvidence = %q, want %q", got.LiveEvidence, LiveEvidenceEvent)
	}
	if strings.Contains(got.Reason, "not confirmed") {
		t.Errorf("Reason still claims the hook is unconfirmed: %q", got.Reason)
	}
}

// Live must never outrank Attached, or the report would claim a hook is doing
// work that is not hooked up at all.
func TestLiveIsNeverTrueWithoutAttached(t *testing.T) {
	tracker := newCapabilityTracker()
	tracker.observe(CapProcessExec)
	rep := buildCapabilityReport(
		"ebpf", true, 1,
		map[CapabilityCategory]capabilityMechanism{
			CapProcessExec: {Mechanism: "ebpf_tracepoint", Attachments: []string{"hook_a"}},
		},
		map[string]bool{}, // nothing attached
		DerivationRuntimeAttach, tracker, "not built",
	)
	got := row(t, rep, CapProcessExec)

	if got.Attached {
		t.Fatal("precondition: nothing should be attached")
	}
	if got.Live || got.Producing {
		t.Errorf("unattached row reported Live=%v Producing=%v", got.Live, got.Producing)
	}
}

func TestSummaryCountsLiveSeparatelyFromAttached(t *testing.T) {
	unconfirmed := livenessReport(t, false).Summary
	if unconfirmed.Attached != 1 {
		t.Fatalf("summary.attached = %d, want 1", unconfirmed.Attached)
	}
	if unconfirmed.Live != 0 {
		t.Errorf("summary.live = %d with no evidence, want 0", unconfirmed.Live)
	}

	confirmed := livenessReport(t, true).Summary
	if confirmed.Live != 1 {
		t.Errorf("summary.live = %d for a producing category, want 1", confirmed.Live)
	}
}

// The retraction must be surgical: it may drop only the generic note, never a
// specific one such as a partial-attach caveat or an active kernel loss.
func TestOnlyTheUnconfirmedNoteIsRetracted(t *testing.T) {
	specific := "lsm_bprm_check is unattached by design"
	st := &CapabilityStatus{Reason: specific}
	clearUnconfirmedReason(st)
	if st.Reason != specific {
		t.Errorf("a specific reason was dropped: %q", st.Reason)
	}

	st = &CapabilityStatus{Reason: reasonAttachedNotConfirmed}
	clearUnconfirmedReason(st)
	if st.Reason != "" {
		t.Errorf("the unconfirmed note survived: %q", st.Reason)
	}

	clearUnconfirmedReason(nil) // must not panic
}

// The console parses these keys; this pins them alongside the existing shape
// test so a rename has to be a deliberate schema change.
func TestLiveKeysAreOnTheWire(t *testing.T) {
	blob, err := json.Marshal(livenessReport(t, true))
	if err != nil {
		t.Fatalf("marshalling report: %v", err)
	}
	raw := string(blob)

	for _, key := range []string{`"live"`, `"live_evidence"`} {
		if !strings.Contains(raw, key) {
			t.Errorf("%s missing from the serialised report", key)
		}
	}
}
