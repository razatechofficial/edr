//go:build !darwin && !linux && !windows

package xdrclient

func readHardwareSerial() string { return "" }
func readProductModel() string   { return "" }
func readManufacturer() string   { return "" }
