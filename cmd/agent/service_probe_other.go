//go:build !windows

package main

import "os"

func runningAsManagedService() bool {
	if os.Getenv("INVOCATION_ID") != "" {
		return true
	}
	return os.Getppid() == 1
}
