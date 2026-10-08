package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/razatechofficial/edr/internal/selfprotect"
)

// The description is what a responder reads first, so it has to say what
// happened to which file and whether the agent put it back.
func TestTheTamperDescriptionSaysWhatHappened(t *testing.T) {
	got := tamperDescription(selfprotect.TamperResponse{
		Path:      "/usr/bin/edr-agent",
		Operation: "WRITE",
		Action:    "restored",
		Restored:  true,
		Timestamp: time.Now(),
	})
	for _, want := range []string{"WRITE", "/usr/bin/edr-agent", "restored", "integrity backup"} {
		if !strings.Contains(got, want) {
			t.Errorf("description %q does not mention %q", got, want)
		}
	}
}

// A failed response must not read as a successful one.
func TestAFailedTamperResponseSaysSo(t *testing.T) {
	got := tamperDescription(selfprotect.TamperResponse{
		Path:      "/etc/edr-agent/config.yml",
		Operation: "REMOVE",
		Action:    "restore_failed",
		Restored:  false,
		Error:     "no backup available",
	})
	if strings.Contains(got, "file restored") {
		t.Errorf("an unrestored file was described as restored: %q", got)
	}
	if !strings.Contains(got, "no backup available") {
		t.Errorf("the failure reason was dropped: %q", got)
	}
}
