package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/razatechofficial/edr/internal/kernel"
)

// stubReporter stands in for a driver. The writer must not care which driver
// produced the report, only that it implements the interface.
type stubReporter struct{ rep kernel.CapabilityReport }

func (s stubReporter) CapabilityReport() kernel.CapabilityReport { return s.rep }

type notAReporter struct{}

func TestWriteCapabilityReportWritesParseableJSON(t *testing.T) {
	dir := t.TempDir()
	want := kernel.CapabilityReport{
		SchemaVersion: kernel.CapabilityReportSchemaVersion,
		Driver:        "ebpf",
		DriverRunning: true,
		Categories: []kernel.CapabilityStatus{
			{Category: kernel.CapProcessExec, Present: true, Attached: true, Producing: true},
		},
		Summary: kernel.CapabilitySummary{Categories: 1, Present: 1, Attached: 1, Producing: 1},
	}

	WriteCapabilityReport(dir, stubReporter{rep: want}, nil)

	path := filepath.Join(dir, CapabilityReportFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var got kernel.CapabilityReport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("report is not parseable JSON: %v", err)
	}
	if got.Driver != "ebpf" || !got.DriverRunning {
		t.Errorf("round-tripped report = %+v, want driver=ebpf running=true", got)
	}
	if len(got.Categories) != 1 || got.Categories[0].Category != kernel.CapProcessExec {
		t.Errorf("categories = %+v, want one process_exec row", got.Categories)
	}
	if got.Summary != want.Summary {
		t.Errorf("summary = %+v, want %+v", got.Summary, want.Summary)
	}

	// No temp file left behind: the console globs this directory.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file was not cleaned up after a successful write")
	}
}

// TestWriteCapabilityReportSkipsNonReporters asserts a driver that cannot
// report produces no file, rather than an empty or misleading one.
func TestWriteCapabilityReportSkipsNonReporters(t *testing.T) {
	dir := t.TempDir()
	WriteCapabilityReport(dir, notAReporter{}, nil)
	if _, err := os.Stat(filepath.Join(dir, CapabilityReportFileName)); !os.IsNotExist(err) {
		t.Error("a driver that does not implement CapabilityReporter must not produce a report file; an absent file is the signal")
	}
}

func TestWriteCapabilityReportEmptyDataDirIsNoOp(t *testing.T) {
	// Must not panic and must not write to the working directory.
	WriteCapabilityReport("", stubReporter{}, nil)
	if _, err := os.Stat(CapabilityReportFileName); !os.IsNotExist(err) {
		t.Error("an empty data dir must not write into the working directory")
	}
}

// TestWriteCapabilityReportOverwrites asserts a second write replaces the
// first, so the console never reads a stale report after a driver restart.
func TestWriteCapabilityReportOverwrites(t *testing.T) {
	dir := t.TempDir()

	WriteCapabilityReport(dir, stubReporter{rep: kernel.CapabilityReport{Driver: "first"}}, nil)
	WriteCapabilityReport(dir, stubReporter{rep: kernel.CapabilityReport{Driver: "second"}}, nil)

	raw, err := os.ReadFile(filepath.Join(dir, CapabilityReportFileName))
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	var got kernel.CapabilityReport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshalling report: %v", err)
	}
	if got.Driver != "second" {
		t.Errorf("driver = %q after a second write, want %q", got.Driver, "second")
	}
}
