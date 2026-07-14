//go:build linux

package keystore

func newPlatformStore(dir, dataDir string) (Store, error) {
	// Prefer hardened sealed files; TPM/PKCS#11 can replace this later.
	return newFileStore(dir, dataDir), nil
}

func newKeychainStore(dir string) (Store, error) {
	return nil, errUnsupported("keychain")
}

func newDPAPIStore(dir string) (Store, error) {
	return nil, errUnsupported("dpapi")
}
