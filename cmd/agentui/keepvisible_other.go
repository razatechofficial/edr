//go:build !windows

package main

func keepConsoleVisible() bool { return false }

func startSensorServicePrivileged() error { return nil }
