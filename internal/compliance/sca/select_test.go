package sca

import (
	"context"
	"runtime"
	"testing"
)

func TestFilterApplicablePoliciesLinux(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("linux host requirements")
	}
	policies := []Policy{
		{
			Policy: PolicyMeta{ID: "match", Name: "match"},
			Requirements: &Requirements{
				Condition: "all",
				Rules:     []string{"f:/proc/sys/kernel/ostype -> Linux"},
			},
		},
		{
			Policy: PolicyMeta{ID: "nomatch", Name: "nomatch"},
			Requirements: &Requirements{
				Condition: "all",
				Rules:     []string{"f:/proc/sys/kernel/ostype -> Windows"},
			},
		},
		{
			Policy: PolicyMeta{ID: "no-req", Name: "no-req"},
		},
	}
	out := FilterApplicablePolicies(context.Background(), policies, defaultEvalConfig(), nil)
	if len(out) != 2 {
		t.Fatalf("expected 2 applicable, got %d: %+v", len(out), out)
	}
}
