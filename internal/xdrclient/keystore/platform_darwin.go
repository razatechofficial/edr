//go:build darwin

package keystore

func newPlatformStore(dir, dataDir string) (Store, error) {
	disk := newFileStore(dir, dataDir)
	kc, err := newKeychainStore(dir)
	if err != nil || kc == nil {
		return disk, nil
	}
	// Keychain is the operator-visible store. Sealed files are the LaunchDaemon
	// fallback: GUI enroll via osascript often lands in the login keychain, which
	// root cannot read.
	return &layeredStore{primary: kc, disk: disk}, nil
}

func newDPAPIStore(dir string) (Store, error) {
	return nil, errUnsupported("dpapi")
}

type layeredStore struct {
	primary Store
	disk    *fileStore
}

func (s *layeredStore) Name() string { return s.primary.Name() }

func (s *layeredStore) Save(m Material) error {
	perr := s.primary.Save(m)
	derr := s.disk.Save(m)
	if perr != nil {
		return perr
	}
	return derr
}

func (s *layeredStore) LoadKeyPEM() ([]byte, error) {
	if b, err := s.primary.LoadKeyPEM(); err == nil && len(b) > 0 {
		return b, nil
	}
	return s.disk.LoadKeyPEM()
}

func (s *layeredStore) LoadCertPEM() ([]byte, error) {
	if b, err := s.primary.LoadCertPEM(); err == nil && len(b) > 0 {
		return b, nil
	}
	return s.disk.LoadCertPEM()
}

func (s *layeredStore) LoadCSRPEM() ([]byte, error) {
	if b, err := s.primary.LoadCSRPEM(); err == nil && len(b) > 0 {
		return b, nil
	}
	return s.disk.LoadCSRPEM()
}

func (s *layeredStore) Has() bool {
	return s.primary.Has() || s.disk.Has()
}

func (s *layeredStore) Clear() error {
	if c, ok := s.primary.(interface{ Clear() error }); ok {
		_ = c.Clear()
	}
	return s.disk.Clear()
}
