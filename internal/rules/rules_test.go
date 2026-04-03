package rules

import "testing"

func TestLoadRuleSet(t *testing.T) {
	rs, err := Load("../../rules/baseline.yaml")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(rs.Rules) == 0 {
		t.Fatal("rules should not be empty")
	}
}
