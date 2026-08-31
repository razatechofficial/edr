//go:build !windows

package main

func windowsServiceRuntimeStatus() string { return "unknown" }
