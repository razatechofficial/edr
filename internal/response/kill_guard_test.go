package response

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/razatechofficial/edr/internal/schema"
)

func killCmd(pid int, name, path string) schema.ResponseCommand {
	return schema.ResponseCommand{
		Action:      schema.ResponseKillProcess,
		ProcessPID:  pid,
		ProcessName: name,
		FilePath:    path,
	}
}

// pid 1 is init on every unix and terminating it panics the kernel.
func TestKillRefusesPidOneOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pid 1 is not init on Windows")
	}
	r := NewResponder(true, nil)
	res := r.Execute(killCmd(1, "someprocess", ""))
	if res.Success {
		t.Fatal("killing pid 1 was permitted")
	}
	if !strings.Contains(res.Message, "pid 1") {
		t.Errorf("message = %q, want it to name pid 1", res.Message)
	}
}

// The agent must not terminate itself or the process supervising it. A
// detection firing on the agent's own activity is exactly the case that
// produces this, and it disables the endpoint.
func TestKillRefusesTheAgentAndItsParent(t *testing.T) {
	r := NewResponder(true, nil)

	if res := r.Execute(killCmd(os.Getpid(), "edr-agent", "")); res.Success {
		t.Error("the agent was allowed to terminate itself")
	}
	if ppid := os.Getppid(); ppid > 1 {
		if res := r.Execute(killCmd(ppid, "parent", "")); res.Success {
			t.Error("the agent was allowed to terminate its parent")
		}
	}
}

// With no operator configuration at all, a critical system process must still
// be refused. This is the shipped default that previously protected nothing.
func TestKillRefusesCriticalProcessWithEmptyOperatorList(t *testing.T) {
	r := NewResponder(true, nil)
	floor := builtinProtected()
	if len(floor) == 0 {
		t.Fatal("this platform has an empty floor")
	}
	// A pid that does not exist, so a refusal can only come from the guard
	// rather than from the kill failing.
	res := r.Execute(killCmd(1<<22, floor[0], ""))
	if res.Success {
		t.Fatalf("%q was terminated despite being in the built-in floor", floor[0])
	}
	if !strings.Contains(res.Message, "protected") {
		t.Errorf("message = %q, want it to say the target is protected", res.Message)
	}
}

// cmd.Reason is free text written by whatever produced the detection. It used
// to be consulted for the target's identity when name and path were empty,
// so an unrelated phrase could decide whether the protection check matched.
func TestReasonIsNotUsedAsTheTargetIdentity(t *testing.T) {
	r := NewResponder(true, []string{"acmed"})
	cmd := killCmd(1<<22, "", "")
	cmd.Reason = "matched rule against /usr/bin/acmed"

	res := r.Execute(cmd)
	if res.Success {
		t.Fatal("a kill with no name or path succeeded")
	}
	if strings.Contains(res.Message, "protected") {
		t.Errorf("the reason text was read as the target's identity: %q", res.Message)
	}
}
