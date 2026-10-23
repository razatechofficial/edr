package kernel

// Tests for the capability self-report's contract.
//
// These run on every OS and exercise the report's semantics with synthetic
// mechanism tables, because the invariants are what the console depends on and
// they must not vary by platform. The per-OS files assert that each driver's
// real table is complete and that attach state is read from the driver rather
// than assumed.

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCanonicalCapabilityCategoriesAreUniqueAndNonEmpty(t *testing.T) {
	if len(CanonicalCapabilityCategories) == 0 {
		t.Fatal("CanonicalCapabilityCategories is empty")
	}
	seen := make(map[CapabilityCategory]bool, len(CanonicalCapabilityCategories))
	for i, c := range CanonicalCapabilityCategories {
		if c == "" {
			t.Errorf("CanonicalCapabilityCategories[%d] is empty", i)
			continue
		}
		if seen[c] {
			t.Errorf("category %q appears twice; the console keys rows on it", c)
		}
		seen[c] = true
	}
}

// TestCapabilityReportCoversEveryCategory asserts a report is never partial.
// A console rendering a fleet matrix cannot distinguish an omitted row from an
// absent capability, so every report carries every canonical category.
func TestCapabilityReportCoversEveryCategory(t *testing.T) {
	rep := emptyCapabilityReport("none", "no driver on this platform")

	if got, want := len(rep.Categories), len(CanonicalCapabilityCategories); got != want {
		t.Fatalf("report has %d categories, want %d (one per canonical category)", got, want)
	}
	for i, want := range CanonicalCapabilityCategories {
		if rep.Categories[i].Category != want {
			t.Errorf("category %d is %q, want %q; report order must match CanonicalCapabilityCategories so the console can render a stable table",
				i, rep.Categories[i].Category, want)
		}
	}
	for _, c := range rep.Categories {
		if c.Present || c.Attached || c.Producing {
			t.Errorf("category %q is flagged on an empty report", c.Category)
		}
		if c.Reason == "" {
			t.Errorf("category %q is absent with no reason; an operator needs to know why", c.Category)
		}
		if c.Derivation != DerivationNotBuilt {
			t.Errorf("category %q derivation is %q, want %q", c.Category, c.Derivation, DerivationNotBuilt)
		}
	}
	if rep.Summary.Categories != len(CanonicalCapabilityCategories) {
		t.Errorf("summary.categories = %d, want %d", rep.Summary.Categories, len(CanonicalCapabilityCategories))
	}
	if rep.Summary.Present != 0 || rep.Summary.Attached != 0 || rep.Summary.Producing != 0 {
		t.Errorf("empty report summary is non-zero: %+v", rep.Summary)
	}
}

// TestCapabilityReportJSONShape pins the wire contract. The console parses
// these keys; renaming one is a breaking change that has to go with a
// CapabilityReportSchemaVersion bump, which this test makes visible.
func TestCapabilityReportJSONShape(t *testing.T) {
	tracker := newCapabilityTracker()
	tracker.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	tracker.observe(CapProcessExec)

	rep := buildCapabilityReport(
		"ebpf", true, 42.5,
		map[CapabilityCategory]capabilityMechanism{
			CapProcessExec: {Mechanism: "ebpf_tracepoint", Attachments: []string{"hook_a"}},
		},
		map[string]bool{"hook_a": true},
		DerivationRuntimeAttach,
		tracker,
		"not built",
	)

	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshalling report: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshalling report: %v", err)
	}

	for _, key := range []string{
		"schema_version", "generated_at", "os", "arch",
		"driver", "driver_running", "uptime_seconds", "categories", "summary",
	} {
		if _, ok := top[key]; !ok {
			t.Errorf("report JSON is missing documented top-level key %q", key)
		}
	}
	if rep.SchemaVersion != CapabilityReportSchemaVersion {
		t.Errorf("schema_version = %d, want %d", rep.SchemaVersion, CapabilityReportSchemaVersion)
	}
	if _, err := time.Parse(time.RFC3339Nano, rep.GeneratedAt); err != nil {
		t.Errorf("generated_at %q is not RFC3339Nano: %v", rep.GeneratedAt, err)
	}

	var cats []map[string]json.RawMessage
	if err := json.Unmarshal(top["categories"], &cats); err != nil {
		t.Fatalf("unmarshalling categories: %v", err)
	}
	// The always-present keys. mechanism, attachments and reason are
	// omitempty by design: an absent category has no mechanism to name.
	for _, key := range []string{"category", "present", "attached", "producing", "events_observed", "last_event_unix", "derivation"} {
		if _, ok := cats[0][key]; !ok {
			t.Errorf("category JSON is missing documented key %q", key)
		}
	}

	exec := findCapability(t, rep, CapProcessExec)
	if !exec.Present || !exec.Attached || !exec.Producing {
		t.Errorf("attached hook with an observed event should be present+attached+producing, got %+v", exec)
	}
	if exec.EventsObserved != 1 {
		t.Errorf("events_observed = %d, want 1", exec.EventsObserved)
	}
	if exec.LastEventUnix != 1_700_000_000 {
		t.Errorf("last_event_unix = %d, want 1700000000", exec.LastEventUnix)
	}
	if exec.Derivation != DerivationRuntimeAttach {
		t.Errorf("derivation = %q, want %q", exec.Derivation, DerivationRuntimeAttach)
	}
}

// TestCapabilityReportInvariants is the heart of the contract: producing
// implies attached implies present, in every state the builder can produce.
// The console's rendering assumes this ordering; without it a row could claim
// to be producing events from a mechanism that is not there.
func TestCapabilityReportInvariants(t *testing.T) {
	mechanisms := map[CapabilityCategory]capabilityMechanism{
		CapProcessExec:    {Mechanism: "m", Attachments: []string{"attached_hook"}},
		CapFileWrite:      {Mechanism: "m", Attachments: []string{"unattached_hook"}, Reason: "loader cannot attach this hook"},
		CapNetworkConnect: {Mechanism: "m", Attachments: []string{"attached_hook", "unattached_hook"}},
	}

	cases := []struct {
		name    string
		running bool
	}{
		{"running", true},
		{"stopped", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tracker := newCapabilityTracker()
			// Observe on every category, including ones that are not
			// attached, so the builder has to gate Producing on
			// Attached rather than trusting the counter.
			for _, c := range CanonicalCapabilityCategories {
				tracker.observe(c)
			}

			rep := buildCapabilityReport("drv", tc.running, 1, mechanisms,
				map[string]bool{"attached_hook": true}, DerivationRuntimeAttach, tracker, "no mechanism")

			for _, c := range rep.Categories {
				if c.Producing && !c.Attached {
					t.Errorf("category %q is producing but not attached", c.Category)
				}
				if c.Attached && !c.Present {
					t.Errorf("category %q is attached but not present", c.Category)
				}
				if !c.Present && (c.Mechanism != "" || len(c.Attachments) > 0) {
					t.Errorf("category %q is absent but names a mechanism %q / attachments %v", c.Category, c.Mechanism, c.Attachments)
				}
				if !c.Attached && c.Present && c.Reason == "" {
					t.Errorf("category %q is present but unattached with no reason", c.Category)
				}
			}

			if !tc.running {
				for _, c := range rep.Categories {
					if c.Attached {
						t.Errorf("category %q is attached while the driver is stopped", c.Category)
					}
					if c.Present && c.Derivation != DerivationDriverStopped {
						t.Errorf("category %q derivation is %q on a stopped driver, want %q", c.Category, c.Derivation, DerivationDriverStopped)
					}
				}
				return
			}

			// Running: check the three interesting rows explicitly.
			exec := findCapability(t, rep, CapProcessExec)
			if !exec.Attached || !exec.Producing {
				t.Errorf("process_exec should be attached and producing, got %+v", exec)
			}

			write := findCapability(t, rep, CapFileWrite)
			if !write.Present {
				t.Error("file_write should be present: a mechanism exists even though it cannot attach")
			}
			if write.Attached {
				t.Error("file_write should not be attached: its only hook is not in the attached set")
			}
			if write.Producing {
				t.Error("file_write should not be producing: an unattached mechanism cannot produce, whatever the counter says")
			}
			if write.Reason != "loader cannot attach this hook" {
				t.Errorf("file_write reason = %q, want the mechanism table's reason", write.Reason)
			}

			// Partial attach: the row reports only the hooks it
			// actually has, not every hook it could have had.
			conn := findCapability(t, rep, CapNetworkConnect)
			if !conn.Attached {
				t.Fatal("network_connect should be attached: one of its two hooks is attached")
			}
			if len(conn.Attachments) != 1 || conn.Attachments[0] != "attached_hook" {
				t.Errorf("network_connect attachments = %v, want only the attached hook; listing an unattached hook would misdirect whoever reads it", conn.Attachments)
			}
		})
	}
}

// TestCapabilityTrackerIgnoresUnknownCategories asserts the hot path cannot be
// made to panic or to grow the map from a decode path that fails to classify
// an event.
func TestCapabilityTrackerIgnoresUnknownCategories(t *testing.T) {
	tracker := newCapabilityTracker()
	before := len(tracker.obs)

	tracker.observe("")
	tracker.observe(CapabilityCategory("not_a_real_category"))

	if got := len(tracker.obs); got != before {
		t.Errorf("tracker map grew from %d to %d on unknown categories; observe must not allocate on the event path", before, got)
	}
	if count, last := tracker.snapshot(CapabilityCategory("not_a_real_category")); count != 0 || last != 0 {
		t.Errorf("unknown category snapshot = (%d, %d), want (0, 0)", count, last)
	}
}

// TestNilCapabilityTrackerIsSafe: a driver built without a tracker (an older
// construction path, or a zero-value struct in a test) must not crash the
// event loop or the report.
func TestNilCapabilityTrackerIsSafe(t *testing.T) {
	var tracker *capabilityTracker
	tracker.observe(CapProcessExec)
	if count, last := tracker.snapshot(CapProcessExec); count != 0 || last != 0 {
		t.Errorf("nil tracker snapshot = (%d, %d), want (0, 0)", count, last)
	}

	rep := buildCapabilityReport("drv", true,
		1, map[CapabilityCategory]capabilityMechanism{
			CapProcessExec: {Mechanism: "m", Attachments: []string{"h"}},
		},
		map[string]bool{"h": true}, DerivationRuntimeAttach, nil, "none")
	exec := findCapability(t, rep, CapProcessExec)
	if exec.Producing {
		t.Error("a driver with no tracker must report producing=false, not claim production it cannot measure")
	}
	if !exec.Attached {
		t.Error("a missing tracker must not affect attach state, which comes from the driver")
	}
}

func TestCapabilitySummaryCountsMatchCategories(t *testing.T) {
	tracker := newCapabilityTracker()
	tracker.observe(CapProcessExec)

	rep := buildCapabilityReport("drv", true, 1,
		map[CapabilityCategory]capabilityMechanism{
			CapProcessExec: {Mechanism: "m", Attachments: []string{"h"}},
			CapFileWrite:   {Mechanism: "m", Attachments: []string{"missing"}, Reason: "r"},
		},
		map[string]bool{"h": true}, DerivationRuntimeAttach, tracker, "none")

	if rep.Summary.Present != 2 {
		t.Errorf("summary.present = %d, want 2", rep.Summary.Present)
	}
	if rep.Summary.Attached != 1 {
		t.Errorf("summary.attached = %d, want 1", rep.Summary.Attached)
	}
	if rep.Summary.Producing != 1 {
		t.Errorf("summary.producing = %d, want 1", rep.Summary.Producing)
	}

	recount := summarizeCapabilities(rep.Categories)
	if recount != rep.Summary {
		t.Errorf("summary %+v does not match a recount of categories %+v", rep.Summary, recount)
	}
}

func findCapability(t *testing.T, rep CapabilityReport, cat CapabilityCategory) CapabilityStatus {
	t.Helper()
	for _, c := range rep.Categories {
		if c.Category == cat {
			return c
		}
	}
	t.Fatalf("report has no category %q", cat)
	return CapabilityStatus{}
}

// isCanonicalCapability reports whether c is one of the report's declared
// categories. Per-OS tables are checked against it so a typo in a category
// string cannot produce a row the console does not know how to render.
func isCanonicalCapability(c CapabilityCategory) bool {
	for _, k := range CanonicalCapabilityCategories {
		if k == c {
			return true
		}
	}
	return false
}
