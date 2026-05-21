package ocsf

import "testing"

func TestFromComplianceScan(t *testing.T) {
	t.Parallel()
	env := FromComplianceScan(ComplianceScanInput{
		EndpointID:         "ep1",
		Hostname:           "host",
		OS:                 "linux",
		Passed:             100,
		Failed:             2,
		PoliciesApplicable: 3,
		DurationMs:         5000,
	}, DefaultProduct("1.0"))
	if env.ClassUID != ClassUIDSecurityFinding {
		t.Fatalf("class_uid=%d", env.ClassUID)
	}
	if env.Unmapped["failed"] != 2 {
		t.Fatalf("failed=%v", env.Unmapped["failed"])
	}
}
