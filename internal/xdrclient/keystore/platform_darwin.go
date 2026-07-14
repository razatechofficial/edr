//go:build darwin

package keystore

func newPlatformStore(dir, dataDir string) (Store, error) {
	if s, err := newKeychainStore(dir); err == nil {
		return s, nil
	}
	return newFileStore(dir, dataDir), nil
}

func newDPAPIStore(dir string) (Store, error) {
	return nil, errUnsupported("dpapi")
}
