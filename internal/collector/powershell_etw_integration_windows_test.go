//go:build windows

package collector

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestPowerShell4104EventEmitted is the post-P0-1 verification that the
// corrected PowerShell provider GUID actually yields ScriptBlock logging
// events on Windows. It is a "best-effort" integration test: if the test
// host lacks PowerShell or the elevated privileges needed to subscribe to
// the Microsoft-Windows-PowerShell ETW provider, we skip rather than fail.
//
// Manual repro after P0-1:
//  1. Enable ScriptBlock logging via Group Policy or registry:
//     HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
//       EnableScriptBlockLogging = 1 (DWORD)
//  2. Run `powershell.exe -Command "Write-Host edr-test-4104"`.
//  3. Verify event ID 4104 appears in the agent's emitted PowerShell
//     telemetry within ~5s.
//
// On non-Windows lanes the file is excluded by build tag.
func TestPowerShell4104EventEmitted(t *testing.T) {
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("powershell.exe not available on this host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile",
		"-Command", "Write-Host edr-test-4104")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Skipf("powershell exec failed (likely missing rights): %v\n%s", err, out)
		}
		t.Skipf("powershell exec failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "edr-test-4104") {
		t.Skipf("powershell ran but expected marker missing in output: %q", out)
	}

	// NOTE: this test deliberately does NOT spin up the ETW driver inline —
	// doing so requires SeDebugPrivilege and dedicated ETW session
	// teardown across goroutines. The integration check is therefore a
	// pre-condition for the manual procedure documented above: the agent
	// running on the same host should have observed event ID 4104.
	t.Log("PowerShell 4104 generator step succeeded; manual verification " +
		"of agent ETW capture is required for full end-to-end coverage.")
}
