package actions

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMergeAllowList_AgentFirst(t *testing.T) {
	t.Parallel()
	out := MergeAllowList("10.0.0.5", []string{"10.0.0.5", "192.168.1.1"})
	if len(out) < 2 || out[0] != "10.0.0.5" {
		t.Fatalf("%v", out)
	}
}

func TestNetworkIsolate_CommandsLinux(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip()
	}
	t.Parallel()
	a := &NetworkIsolateAction{
		AllowList:       []string{"192.168.0.2"},
		DurationMinutes: 30,
		BackupPath:      filepath.Join(t.TempDir(), "ipt.bak"),
		AgentIP:         "10.0.0.1",
	}
	cmds := a.PrepareCommands()
	if len(cmds) == 0 {
		t.Fatal("no commands")
	}
	if runtime.GOOS == "linux" {
		if !strings.Contains(cmds[0], "iptables-save") {
			t.Fatalf("%v", cmds)
		}
		var hasAllow bool
		for _, c := range cmds {
			if strings.Contains(c, "10.0.0.1") && strings.Contains(c, "ACCEPT") {
				hasAllow = true
			}
		}
		if !hasAllow {
			t.Fatalf("agent IP not in allow rules: %v", cmds)
		}
	}
}

func TestNetworkIsolate_CommandsWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip()
	}
	t.Parallel()
	a := &NetworkIsolateAction{AllowList: []string{"1.1.1.1"}, AgentIP: "10.0.0.1", BackupPath: "C:\\tmp\\b.wfw"}
	cmds := a.PrepareCommands()
	if len(cmds) == 0 {
		t.Fatal("no commands")
	}
	if !strings.Contains(cmds[len(cmds)-1], "EDR-Allow") {
		t.Fatalf("%v", cmds)
	}
}
