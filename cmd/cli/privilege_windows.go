//go:build windows

package main

import "golang.org/x/sys/windows"

func processPrivileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func privilegeDeniedMessage() string {
	return "this command requires Administrator; re-run from an elevated prompt"
}
