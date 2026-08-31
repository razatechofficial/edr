//go:build !windows

package main

import "fmt"

func windowsControlAgentService(action string) error {
	return fmt.Errorf("windows service control is not available on this OS (%s)", action)
}
