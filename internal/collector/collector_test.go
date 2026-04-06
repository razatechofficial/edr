package collector

import "testing"

func TestParsePSLine(t *testing.T) {
	pid, ppid, cmdline, ok := parsePSLine(" 123  1 /bin/bash -c whoami")
	if !ok {
		t.Fatal("expected parse success")
	}
	if pid != 123 || ppid != 1 {
		t.Fatalf("unexpected pids: %d %d", pid, ppid)
	}
	if cmdline != "/bin/bash -c whoami" {
		t.Fatalf("unexpected cmdline: %s", cmdline)
	}
}

func TestFilepathBase(t *testing.T) {
	if got := filepathBase("/usr/bin/curl"); got != "curl" {
		t.Fatalf("unexpected base: %s", got)
	}
}

func TestFirstArg(t *testing.T) {
	if got := firstArg("/tmp/sleep_edr_test 30"); got != "/tmp/sleep_edr_test" {
		t.Fatalf("unexpected first arg: %s", got)
	}
}
