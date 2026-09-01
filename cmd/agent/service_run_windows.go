//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
)

type edrWindowsService struct {
	configPath string
}

func (s *edrWindowsService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runAgentCore(ctx, s.configPath)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(8 * time.Second):
				}
				return false, 0
			default:
			}
		}
	}
}

// tryRunWindowsService runs under the Service Control Manager when invoked as a service.
// Returns (handled, exitCode).
func tryRunWindowsService() (bool, int) {
	// msiexec deferred custom actions run in session 0; IsWindowsService
	// can be a false positive, which skipped --install and left no EDRAgent.
	for _, a := range os.Args[1:] {
		if a == "--install" || a == "--uninstall" || a == "--msi-stop" {
			return false, 0
		}
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "windows service probe: %v\n", err)
		return false, 0
	}
	if !isService {
		return false, 0
	}
	configPath := windowsConfigFromArgs()
	s := &edrWindowsService{configPath: configPath}
	if err := svc.Run(windowsServiceName, s); err != nil {
		fmt.Fprintf(os.Stderr, "windows service run: %v\n", err)
		return true, 1
	}
	return true, 0
}
