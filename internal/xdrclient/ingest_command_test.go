package xdrclient

import "testing"

func TestMapRemoteCommandType(t *testing.T) {
	cases := map[string]string{
		"COMMAND_TYPE_KILL_PROCESS": "kill_process",
		"kill_process":              "kill_process",
		"COMMAND_TYPE_ISOLATE_HOST": "network_isolate",
		"COMMAND_TYPE_COLLECT_FORENSIC": "collect_forensics",
	}
	for in, want := range cases {
		if got := MapRemoteCommandType(in); got != want {
			t.Fatalf("%q -> %q want %q", in, got, want)
		}
	}
}
