package rules

import "testing"

func TestMITREMapperMapSigmaTag(t *testing.T) {
	t.Parallel()
	m := NewMITREMapper()

	result := m.MapSigmaTag("attack.t1059.001")
	if result == nil {
		t.Fatal("MapSigmaTag returned nil for attack.t1059.001")
	}
	if result.TechniqueID != "T1059.001" {
		t.Errorf("TechniqueID = %q, want %q", result.TechniqueID, "T1059.001")
	}
	if result.TechniqueName != "PowerShell" {
		t.Errorf("TechniqueName = %q, want %q", result.TechniqueName, "PowerShell")
	}
}

func TestMITREMapperMapTacticTag(t *testing.T) {
	t.Parallel()
	m := NewMITREMapper()

	result := m.MapSigmaTag("attack.initial_access")
	if result == nil {
		t.Fatal("MapSigmaTag returned nil for attack.initial_access")
	}
	if result.TacticID != "TA0001" {
		t.Errorf("TacticID = %q, want %q", result.TacticID, "TA0001")
	}
	if result.TacticName != "Initial Access" {
		t.Errorf("TacticName = %q, want %q", result.TacticName, "Initial Access")
	}
}

func TestMITREMapperUnknownTag(t *testing.T) {
	t.Parallel()
	m := NewMITREMapper()

	tests := []string{
		"attack.unknown_tactic",
		"not.attack.tag",
		"",
		"attack.",
	}
	for _, tag := range tests {
		if result := m.MapSigmaTag(tag); result != nil {
			t.Errorf("MapSigmaTag(%q) = non-nil, want nil", tag)
		}
	}
}

func TestMITREMapperMapTechnique(t *testing.T) {
	t.Parallel()
	m := NewMITREMapper()

	tests := []struct {
		id       string
		wantName string
	}{
		{"T1059.001", "PowerShell"},
		{"T1486", "Data Encrypted for Impact"},
		{"T1055.012", "Process Hollowing"},
	}
	for _, tc := range tests {
		result := m.MapTechnique(tc.id)
		if result == nil {
			t.Errorf("MapTechnique(%q) = nil", tc.id)
			continue
		}
		if result.TechniqueName != tc.wantName {
			t.Errorf("MapTechnique(%q).TechniqueName = %q, want %q",
				tc.id, result.TechniqueName, tc.wantName)
		}
	}
}
