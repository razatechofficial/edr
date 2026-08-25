//go:build !darwin && !windows

package main

func needsFullDiskAccess() bool { return false }

func hasFullDiskAccess() bool { return true }

func openOSGrantSettings() error { return nil }
