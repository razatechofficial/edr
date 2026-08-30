//go:build !windows

package main

func windowsIsAdmin() bool { return false }
