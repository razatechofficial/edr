//go:build linux

package kernel

import (
	"errors"
	"testing"
)

func TestIsOptionalTracepointAttachFailure(t *testing.T) {
	err := errors.New("cannot create bpf perf link: permission denied")
	optional := []struct {
		group, tp string
	}{
		{"syscalls", "sys_enter_fchmodat"},
		{"syscalls", "sys_enter_setgid"},
		{"syscalls", "sys_enter_setuid"},
		{"syscalls", "sys_enter_setreuid"},
		{"syscalls", "sys_enter_setregid"},
		{"syscalls", "sys_enter_setresuid"},
		{"syscalls", "sys_enter_setresgid"},
	}
	for _, tc := range optional {
		if !isOptionalTracepointAttachFailure(tc.group, tc.tp, err) {
			t.Fatalf("expected optional attach failure for %s/%s", tc.group, tc.tp)
		}
	}
	if isOptionalTracepointAttachFailure("syscalls", "sys_enter_execve", err) {
		t.Fatal("execve attach failure must not be optional")
	}
}
