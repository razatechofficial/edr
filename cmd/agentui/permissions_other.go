//go:build !darwin

package main

func needsFullDiskAccess() bool { return false }

func hasFullDiskAccess() bool { return true }

func openFullDiskAccessSettings() error { return nil }
