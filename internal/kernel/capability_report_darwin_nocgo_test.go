//go:build darwin && (!cgo || nosec)

package kernel

// macOS capability report test for builds without the ESF bridge.

import (
	"strings"
	"testing"
)

// TestDarwinNocgoCapabilityReportIsCompleteAndAbsent asserts the stub build
// still answers with a full category matrix. A console that gets no answer
// cannot tell "not monitoring" from "did not respond", so the answer has to be
// an explicit all-absent report with an actionable reason.
func TestDarwinNocgoCapabilityReportIsCompleteAndAbsent(t *testing.T) {
	d := &ESFDriver{}
	rep := d.CapabilityReport()

	if rep.Driver != "esf" {
		t.Errorf("driver = %q, want esf", rep.Driver)
	}
	if rep.DriverRunning {
		t.Error("driver_running should be false in a build with no ESF bridge")
	}
	if got, want := len(rep.Categories), len(CanonicalCapabilityCategories); got != want {
		t.Fatalf("report has %d categories, want %d", got, want)
	}
	if rep.Summary.Present != 0 || rep.Summary.Attached != 0 || rep.Summary.Producing != 0 {
		t.Errorf("summary should be all zero in a build with no driver: %+v", rep.Summary)
	}
	for _, c := range rep.Categories {
		if c.Present {
			t.Errorf("category %q is present in a build with no ESF bridge", c.Category)
		}
		if !strings.Contains(c.Reason, "cgo") {
			t.Errorf("category %q reason = %q, want it to name cgo as the cause so the fix is obvious", c.Category, c.Reason)
		}
	}
}
