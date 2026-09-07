//go:build !windows

package main

func writeServiceLastError(error) {}

func windowsDataRootForLogs() string { return "" }

func hasServiceConfigArg() bool { return false }

func writeAgentBoot(string) {}
