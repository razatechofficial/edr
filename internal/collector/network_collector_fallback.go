//go:build !darwin

package collector

func darwinLsofConnections() []connEntry { return nil }
