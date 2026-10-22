package response

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The floor must hold with an empty operator list. That is the configuration
// the agent shipped — protected_processes: [] — and it meant nothing was
// protected at all.
func TestBuiltinFloorHoldsWithNoOperatorConfiguration(t *testing.T) {
	set := newProtectedSet(nil)
	for _, name := range builtinProtected() {
		if _, ok := set.covers(name, ""); !ok {
			t.Errorf("%q is in the built-in floor but newProtectedSet(nil) does not cover it", name)
		}
	}
}

// Each platform's list must contain the processes whose termination takes the
// machine down. Asserted per platform rather than only for the host's, because
// a floor checked on one operating system is two thirds unverified.
func TestEveryPlatformProtectsItsFatalProcesses(t *testing.T) {
	mustHave := map[string][]string{
		// Terminating any of these bugchecks Windows.
		"windows": {"csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe", "smss.exe", "svchost.exe"},
		// launchd is pid 1; WindowServer and loginwindow own the session.
		"darwin": {"launchd", "kernel_task", "windowserver", "loginwindow", "opendirectoryd", "securityd"},
		// pid 1 under its usual names, plus the daemon that keeps a headless
		// host reachable at all.
		"linux": {"systemd", "init", "sshd", "dbus-daemon", "auditd"},
	}
	for goos, names := range mustHave {
		got := make(map[string]struct{})
		for _, n := range builtinProtectedFor(goos) {
			got[strings.ToLower(n)] = struct{}{}
		}
		for _, want := range names {
			if _, ok := got[want]; !ok {
				t.Errorf("%s floor does not protect %q", goos, want)
			}
		}
	}
}

// An operator list adds to the floor; it must not replace it.
func TestOperatorEntriesAddToTheFloor(t *testing.T) {
	set := newProtectedSet([]string{"my-database"})
	if _, ok := set.covers("my-database", ""); !ok {
		t.Error("operator entry was not honoured")
	}
	floor := builtinProtected()
	if len(floor) == 0 {
		t.Fatal("this platform has an empty floor")
	}
	if _, ok := set.covers(floor[0], ""); !ok {
		t.Errorf("configuring an operator list dropped the floor entry %q", floor[0])
	}
}

// A path entry is matched as a path, and also by its base name so a match
// still happens when only the name is known.
func TestPathEntriesMatchByPathAndName(t *testing.T) {
	p := filepath.Join(string(filepath.Separator), "opt", "acme", "acmed")
	set := newProtectedSet([]string{p})

	if _, ok := set.covers("", p); !ok {
		t.Error("exact path was not covered")
	}
	if _, ok := set.covers("acmed", ""); !ok {
		t.Error("base name of a path entry was not covered")
	}
}

// Names are compared case-insensitively: Windows and macOS paths vary in case
// for the same binary, and a check that misses on case is a check that is not
// there.
func TestNameMatchingIgnoresCase(t *testing.T) {
	set := newProtectedSet([]string{"AcmeAgent"})
	for _, probe := range []string{"acmeagent", "ACMEAGENT", "AcmeAgent"} {
		if _, ok := set.covers(probe, ""); !ok {
			t.Errorf("%q was not covered", probe)
		}
	}
}

// A process whose name is not protected must not be covered, or the floor
// would refuse every termination and the feature would be dead rather than
// safe.
func TestUnprotectedProcessIsNotCovered(t *testing.T) {
	set := newProtectedSet(nil)
	if why, ok := set.covers("definitely-not-a-system-process", "/tmp/x/definitely-not-a-system-process"); ok {
		t.Errorf("an ordinary process was reported protected: %s", why)
	}
}

// Case folding of paths must follow the filesystem: on Linux two paths
// differing in case are two different files, and folding them would protect a
// binary the operator never named.
func TestPathCaseFollowsTheFilesystem(t *testing.T) {
	set := newProtectedSet([]string{"/opt/Acme/acmed"})
	_, ok := set.covers("", "/opt/ACME/acmed")
	switch runtime.GOOS {
	case "linux":
		if ok {
			t.Error("linux paths were folded; /opt/ACME/acmed is a different file from /opt/Acme/acmed")
		}
	default:
		if !ok {
			t.Error("path matching on a case-insensitive filesystem missed a case variant")
		}
	}
}
