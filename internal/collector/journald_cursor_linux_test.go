//go:build linux

package collector

import "testing"

func Test_journaldMessageFromJSONLine(t *testing.T) {
	line := `{"__CURSOR":"c1","MESSAGE":"hello"}`
	msg, cur := journaldMessageFromJSONLine(line)
	if cur != "c1" || msg != "hello" {
		t.Fatalf("msg=%q cur=%q", msg, cur)
	}
}
