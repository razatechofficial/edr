package main

import (
	"testing"

	"github.com/razatechofficial/edr/internal/platform"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func TestApplyLocalEnrollmentFromLiveIngest(t *testing.T) {
	st := operatorStatus{IngestOK: true, Service: "running"}
	applyLocalEnrollment(&st)
	if !st.Enrolled {
		t.Fatal("live ingest must count as enrolled so the GUI does not reopen Enroll")
	}
}

func TestApplyLocalEnrollmentFromConfiguredRunningSensor(t *testing.T) {
	st := operatorStatus{IngestConfigured: true, Service: "running"}
	applyLocalEnrollment(&st)
	if !st.Enrolled {
		t.Fatal("running sensor with ingest configured must count as enrolled")
	}
}

func TestApplyLocalEnrollmentIdleInstall(t *testing.T) {
	if xdrclient.ProbeLocalEnrollment(platform.ResolveConfigFile(), platform.DataDir()).Enrolled {
		t.Skip("this machine already has a local enrollment sidecar")
	}
	st := operatorStatus{Service: "not running"}
	applyLocalEnrollment(&st)
	if st.Enrolled {
		t.Fatal("a stopped sensor with no identity must not look enrolled")
	}
}
