//go:build !darwin

package main

func wrapDarwinSensorApp(bin string) (string, error) {
	return bin, nil
}
