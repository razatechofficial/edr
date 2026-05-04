//go:build !cgo

package collector

func cgoEnabledForProbe() bool { return false }
