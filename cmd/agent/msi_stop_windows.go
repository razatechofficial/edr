//go:build windows

package main

import (
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// msiStopForReplace is invoked by the MSI before StopServices so upgrade /
// uninstall can replace files. Closing the operator UI does not stop EDRAgent.
func msiStopForReplace() error {
	killImage("edr-agent-ui.exe")

	m, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer m.Disconnect()
	s, err := m.OpenService(windowsServiceName)
	if err != nil {
		return nil
	}
	defer s.Close()

	_ = s.SetRecoveryActions(nil, 0)

	st, qerr := s.Query()
	if qerr == nil && st.State == svc.Stopped {
		return nil
	}
	_, _ = s.Control(svc.Stop)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		st, err = s.Query()
		if err == nil && st.State == svc.Stopped {
			return nil
		}
		time.Sleep(400 * time.Millisecond)
	}
	st, err = s.Query()
	if err == nil && st.ProcessId != 0 && int(st.ProcessId) != os.Getpid() {
		terminatePID(st.ProcessId)
	}
	return nil
}

func killImage(name string) {
	cmd := exec.Command("taskkill.exe", "/F", "/IM", name, "/T")
	hideConsole(cmd)
	_ = cmd.Run()
}

func terminatePID(pid uint32) {
	if pid == 0 {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	_ = windows.TerminateProcess(h, 1)
}
