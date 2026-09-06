//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func windowsServiceRuntimeStatus() string {
	s, closer, err := openEDRAgent(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "not installed"
	}
	defer closer()
	st, err := s.Query()
	if err != nil {
		return "unknown"
	}
	switch st.State {
	case svc.Running:
		return "running"
	case svc.Stopped:
		return "stopped"
	case svc.StartPending, svc.ContinuePending:
		return "starting"
	default:
		return "installed"
	}
}
