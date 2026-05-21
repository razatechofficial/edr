package ocsf

import (
	"testing"
	"time"
)

func TestFromComplianceFinding(t *testing.T) {
	t.Parallel()
	env := FromComplianceFinding(ComplianceInput{
		EndpointID: "ep-1",
		Hostname:   "host",
		OS:         "linux",
		PolicyID:   "cis_linux",
		PolicyName: "CIS Linux",
		CheckID:    36000,
		Title:      "cramfs disabled",
		Result:     "failed",
		Compliance: map[string][]string{"pci_dss": {"2.2"}},
		Timestamp:  time.Unix(1, 0).UTC(),
	}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDSecurityFinding {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
	if env.Finding == nil || env.Finding.Title != "cramfs disabled" {
		t.Fatalf("finding=%+v", env.Finding)
	}
	if env.Severity != "Medium" {
		t.Fatalf("severity=%q", env.Severity)
	}
}

func TestFromProcess(t *testing.T) {
	t.Parallel()
	env := FromProcess(ProcessInput{
		EndpointID:  "ep-1",
		Timestamp:   time.Unix(2, 0).UTC(),
		PID:         42,
		ProcessName: "bash",
		ProcessPath: "/bin/bash",
		CommandLine: "-l",
	}, DefaultProduct("test"))
	if env.ClassUID != ClassUIDProcessActivity {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
	if env.Process == nil || env.Process.Name != "bash" {
		t.Fatalf("process=%+v", env.Process)
	}
}
