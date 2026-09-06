//go:build windows

package hostperm

import "testing"

func TestProcessStillActiveZero(t *testing.T) {
	if processStillActive(0) {
		t.Fatal("pid 0 must not look alive")
	}
}
