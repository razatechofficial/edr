//go:build !darwin && !windows && !linux

package keystore

func newPlatformStore(dir, dataDir string) (Store, error) {
	return newFileStore(dir, dataDir), nil
}

func newKeychainStore(dir string) (Store, error) {
	return nil, errUnsupported("keychain")
}

func newDPAPIStore(dir string) (Store, error) {
	return nil, errUnsupported("dpapi")
}
