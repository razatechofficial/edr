//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// msiStopForReplace force-stops EDRAgent and the operator UI so files can be
// replaced. The MSI no longer shells this binary (old builds ignored --msi-stop
// and started the sensor inside msiexec). Keep the flag for a manual cleanup.
func msiStopForReplace() error {
	self := os.Getpid()
	killImage("edr-agent-ui.exe")

	m, err := mgr.Connect()
	if err == nil {
		defer m.Disconnect()
		if s, oerr := m.OpenService(windowsServiceName); oerr == nil {
			_ = s.SetRecoveryActions(nil, 0)
			st, qerr := s.Query()
			if qerr != nil || st.State != svc.Stopped {
				_, _ = s.Control(svc.Stop)
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					st, err = s.Query()
					if err == nil && st.State == svc.Stopped {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				st, err = s.Query()
				if err == nil && st.ProcessId != 0 && int(st.ProcessId) != self {
					terminatePID(st.ProcessId)
				}
			}
			_ = s.Close()
		}
	}

	killOtherImage("edr-agent.exe", self)
	return nil
}

func killImage(name string) {
	cmd := exec.Command("taskkill.exe", "/F", "/IM", name, "/T")
	hideConsole(cmd)
	_ = cmd.Run()
}

func killOtherImage(name string, exceptPID int) {
	cmd := exec.Command("taskkill.exe", "/F", "/IM", name, "/T", "/FI", fmt.Sprintf("PID ne %d", exceptPID))
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
