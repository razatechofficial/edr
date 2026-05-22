package selfprotect

import "testing"

func TestResolveLaunchProtectedTier(t *testing.T) {
	tests := []struct {
		tier    string
		legacy  bool
		level   uint32
		name    string
		enabled bool
	}{
		{"", false, ServiceLaunchProtectedNone, "none", false},
		{"", true, ServiceLaunchProtectedWindowsLight, "windows_light", true},
		{"antimalware_light", false, ServiceLaunchProtectedAntimalwareLight, "antimalware_light", true},
		{"ppl", false, ServiceLaunchProtectedAntimalwareLight, "antimalware_light", true},
		{"none", true, ServiceLaunchProtectedNone, "none", false},
	}
	for _, tc := range tests {
		lvl, name, enabled := ResolveLaunchProtectedTier(tc.tier, tc.legacy)
		if lvl != tc.level || name != tc.name || enabled != tc.enabled {
			t.Fatalf("ResolveLaunchProtectedTier(%q,%v) = (%d,%q,%v) want (%d,%q,%v)",
				tc.tier, tc.legacy, lvl, name, enabled, tc.level, tc.name, tc.enabled)
		}
	}
}

func TestProtectionLevelName(t *testing.T) {
	if ProtectionLevelName(ProtectionLevelAntimalwareLight) != "antimalware_light" {
		t.Fatal("unexpected antimalware name")
	}
	if !IsAntimalwareProtectionLevel(ProtectionLevelAntimalwareLight) {
		t.Fatal("expected antimalware level")
	}
}
