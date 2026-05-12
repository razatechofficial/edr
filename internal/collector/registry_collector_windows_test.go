//go:build windows

package collector

import (
	"strings"
	"testing"
)

// TestRegistryCollectorPersistenceCoverage pins the watch list against the
// canonical set of persistence locations established by the P0-9 audit.
// New persistence techniques surface in MITRE ATT&CK regularly; if the
// production list drops one of these without updating this test we want
// to know on the next CI run.
func TestRegistryCollectorPersistenceCoverage(t *testing.T) {
	required := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SYSTEM\CurrentControlSet\Services`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		// P0-9 additions:
		`HKLM\SOFTWARE\Classes\CLSID`,
		`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`,
		`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB`,
		`HKCU\Environment`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`,
	}
	rc := NewRegistryCollector("endpoint-test")
	got := make(map[string]struct{}, len(rc.watchKeys))
	for _, k := range rc.watchKeys {
		got[k] = struct{}{}
	}
	var missing []string
	for _, k := range required {
		if _, ok := got[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("RegistryCollector watch list missing keys:\n  %s",
			strings.Join(missing, "\n  "))
	}
}
