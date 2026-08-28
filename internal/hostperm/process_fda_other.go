//go:build !darwin

package hostperm

func ProcessHasFDA() bool { return true }
