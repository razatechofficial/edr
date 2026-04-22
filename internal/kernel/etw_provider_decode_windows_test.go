//go:build windows

package kernel

import (
	"testing"
	"unsafe"
)

func utf16LEBytes(s string) []byte {
	out := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return append(out, 0, 0)
}

func TestDecodePowerShell4104(t *testing.T) {
	ud := append([]byte{1, 0, 0, 0, 1, 0, 0, 0}, utf16LEBytes("Invoke-Expression")...)
	env := map[string]interface{}{}
	decodePowerShellEtw(4104, ud, env)
	if env["script_block"] != "Invoke-Expression" {
		t.Fatalf("script_block: %v", env["script_block"])
	}
}

func TestDecodeStructuredETW_WMI(t *testing.T) {
	ud := make([]byte, 64)
	copy(ud[16:], utf16LEBytes("root\\subscription"))
	env := map[string]interface{}{}
	decodeWMIEtw(5861, ud, env)
	if env["message"] != "root\\subscription" {
		t.Fatalf("message: %v", env)
	}
}

func TestDecodeStructuredETW_Task(t *testing.T) {
	ud := utf16LEBytes(`\Microsoft\Windows\Task`)
	env := map[string]interface{}{}
	decodeTaskSchedulerEtw(106, ud, env)
	if env["task_name"] != `\Microsoft\Windows\Task` {
		t.Fatalf("task_name: %v", env)
	}
}

func TestDecodeStructuredETW_EndToEnd(t *testing.T) {
	d := &ETWDriver{}
	ud := append([]byte{1, 0, 0, 0, 1, 0, 0, 0}, utf16LEBytes("Get-Process")...)
	rec := &etwEventRecord{
		EventHeader: etwEventHeader{
			ProviderId: powershellGUID,
			EventDescriptor: etwEventDescriptor{
				Id: 4104,
			},
		},
		UserData:       uintptr(unsafe.Pointer(&ud[0])),
		UserDataLength: uint16(len(ud)),
	}
	env := map[string]interface{}{}
	d.decodeStructuredETW(rec, env)
	if env["script_block"] != "Get-Process" {
		t.Fatalf("expected script_block, got %#v", env)
	}
}
