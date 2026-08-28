//go:build !darwin && !windows

package main

import "github.com/razatechofficial/edr/internal/hostperm"

func needsFullDiskAccess() bool { return false }

func hasFullDiskAccess() bool { return true }

func openOSGrantSettings() error { return hostperm.OpenSettings("") }
