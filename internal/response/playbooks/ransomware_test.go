package playbooks

import "testing"

func TestRansomwarePlaybookSteps(t *testing.T) {
	t.Parallel()
	pb := NewRansomwarePlaybook()
	if got := len(pb.Steps()); got != 12 {
		t.Errorf("step count = %d, want 12", got)
	}
}

func TestRansomwarePlaybookName(t *testing.T) {
	t.Parallel()
	pb := NewRansomwarePlaybook()
	if got := pb.Name(); got != "ransomware_response" {
		t.Errorf("Name() = %q, want %q", got, "ransomware_response")
	}
}
