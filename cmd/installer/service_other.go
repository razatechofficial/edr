//go:build !windows

package main

import "fmt"

func installWindowsService(string, string) error {
	return fmt.Errorf("windows service install is not supported on this OS")
}

func stopWindowsService() error {
	return fmt.Errorf("windows service stop is not supported on this OS")
}

func removeWindowsService() error {
	return fmt.Errorf("windows service remove is not supported on this OS")
}
