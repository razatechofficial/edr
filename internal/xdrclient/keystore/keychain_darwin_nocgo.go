//go:build darwin && !cgo

package keystore

func newKeychainStore(dir string) (Store, error) {
	return nil, errUnsupported("keychain (requires CGO_ENABLED=1)")
}
