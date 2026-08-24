//go:build !windows && !darwin && !linux

package main

func checkRequiredHostAccess() error { return nil }
