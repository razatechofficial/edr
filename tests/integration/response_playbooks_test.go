package integration

import (
	"testing"

	"github.com/razatechofficial/edr/internal/response/playbooks"
	"github.com/razatechofficial/edr/pkg/events"
)

func TestDisruptivePlaybookStepsRequireApproval(t *testing.T) {
	t.Parallel()

	check := func(t *testing.T, name string, pb *playbooks.BasePlaybook) {
		t.Helper()
		for _, step := range pb.Steps() {
			if step.Name == "kill_process_tree" || step.Name == "kill_rat_process" || step.Name == "kill_process" || step.Name == "network_isolate" || step.Name == "network_isolate_process" {
				params := step.Params(&events.Alert{})
				if req, ok := params["requires_approval"].(bool); !ok || !req {
					t.Fatalf("%s step %q missing requires_approval=true", name, step.Name)
				}
			}
		}
	}

	check(t, "ransomware", playbooks.NewRansomwarePlaybook())
	check(t, "rat", playbooks.NewRATPlaybook())
	check(t, "credential_dump", playbooks.NewCredentialDumpPlaybook())
	check(t, "lateral_movement", playbooks.NewLateralMovementPlaybook())
	check(t, "data_exfiltration", playbooks.NewDataExfiltrationPlaybook())
}
