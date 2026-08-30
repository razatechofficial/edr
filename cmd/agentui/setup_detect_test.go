package main

import "testing"

func TestRunningAttendedSetupDetectsNames(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/Users/me/Downloads/EDR-Agent-Setup.app/Contents/MacOS/edr-agent-ui", true},
		{`C:\Users\me\Downloads\EDR-Agent-Setup.exe`, true},
		{"/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui", false},
		{`C:\Program Files\EDR Agent\edr-agent-ui.exe`, false},
	}
	for _, tc := range cases {
		if got := attendedSetupPath(tc.path); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.path, got, tc.want)
		}
	}
}
