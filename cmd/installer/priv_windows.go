//go:build windows

package main

import "golang.org/x/sys/windows"

func windowsIsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
