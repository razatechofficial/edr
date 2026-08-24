//go:build windows

package main

import "golang.org/x/sys/windows/svc"

func runningAsManagedService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}
