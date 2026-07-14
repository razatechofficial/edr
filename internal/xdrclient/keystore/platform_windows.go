//go:build windows

package keystore

func newPlatformStore(dir, dataDir string) (Store, error) {
	if s, err := newDPAPIStore(dir); err == nil {
		return s, nil
	}
	return newFileStore(dir, dataDir), nil
}

func newKeychainStore(dir string) (Store, error) {
	return nil, errUnsupported("keychain")
}
