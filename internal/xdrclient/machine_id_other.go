//go:build !linux && !darwin && !windows

package xdrclient

func platformSystemUUID() string { return "" }
