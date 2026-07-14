//go:build !darwin

package keystore

func darwinPlatformUUID() string { return "" }
