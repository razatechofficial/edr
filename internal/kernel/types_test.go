package kernel

import (
	"testing"
	"time"
)

func TestDefaultPolicy(t *testing.T) {
	t.Parallel()
	p := DefaultPolicy()

	fields := []struct {
		name string
		val  bool
	}{
		{"ProcessEvents", p.ProcessEvents},
		{"FileEvents", p.FileEvents},
		{"NetworkEvents", p.NetworkEvents},
		{"RegistryEvents", p.RegistryEvents},
		{"MemoryEvents", p.MemoryEvents},
		{"DNSEvents", p.DNSEvents},
		{"AuthEvents", p.AuthEvents},
		{"ModuleEvents", p.ModuleEvents},
		{"MountEvents", p.MountEvents},
		{"PtraceEvents", p.PtraceEvents},
		{"SignalEvents", p.SignalEvents},
	}
	for _, f := range fields {
		if !f.val {
			t.Errorf("DefaultPolicy().%s = false, want true", f.name)
		}
	}

	if len(p.MutePaths) != 0 {
		t.Errorf("DefaultPolicy().MutePaths should be empty, got %d", len(p.MutePaths))
	}
	if len(p.MutePIDs) != 0 {
		t.Errorf("DefaultPolicy().MutePIDs should be empty, got %d", len(p.MutePIDs))
	}
}

func TestDriverStats(t *testing.T) {
	t.Parallel()
	var s DriverStats

	if s.EventsReceived != 0 {
		t.Errorf("EventsReceived = %d, want 0", s.EventsReceived)
	}
	if s.EventsDropped != 0 {
		t.Errorf("EventsDropped = %d, want 0", s.EventsDropped)
	}
	if s.EventsProcessed != 0 {
		t.Errorf("EventsProcessed = %d, want 0", s.EventsProcessed)
	}
	if !s.LastEventTime.IsZero() {
		t.Errorf("LastEventTime should be zero, got %v", s.LastEventTime)
	}
	if s.UptimeSeconds != 0 {
		t.Errorf("UptimeSeconds = %f, want 0", s.UptimeSeconds)
	}
	if s.ErrorCount != 0 {
		t.Errorf("ErrorCount = %d, want 0", s.ErrorCount)
	}
}

var _ = time.Now // keep import
