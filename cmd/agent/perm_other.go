//go:build !windows && !darwin && !linux

package main

func checkRequiredHostAccess() error { return nil }

func hostAccessWarning() string { return "" }
