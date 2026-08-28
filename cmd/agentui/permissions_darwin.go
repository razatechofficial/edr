//go:build darwin

package main

import "github.com/razatechofficial/edr/internal/hostperm"

func needsFullDiskAccess() bool { return true }

func hasFullDiskAccess() bool {
	rep := hostperm.EvaluateQuick()
	for _, it := range rep.Items {
		if it.ID == hostperm.IDFDA {
			return it.Status == hostperm.StatusOK
		}
	}
	return false
}

func openOSGrantSettings() error { return hostperm.OpenSettings(hostperm.IDFDA) }
