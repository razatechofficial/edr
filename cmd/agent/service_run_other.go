//go:build !windows

package main

func tryRunWindowsService() (bool, int) {
	return false, 0
}
