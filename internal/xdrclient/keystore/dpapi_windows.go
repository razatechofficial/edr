//go:build windows

package keystore

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dpapiKeyFile  = "agent.key.dpapi"
	dpapiCertFile = "agent.crt.dpapi"
	dpapiCSRFile  = "agent.csr.dpapi"
)

type dpapiStore struct {
	dir string
}

func newDPAPIStore(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Probe DPAPI with a tiny round-trip.
	probe := []byte("xdr-dpapi-probe")
	enc, err := dpapiProtect(probe)
	if err != nil {
		return nil, err
	}
	dec, err := dpapiUnprotect(enc)
	if err != nil || string(dec) != string(probe) {
		return nil, fmt.Errorf("dpapi probe failed: %w", err)
	}
	return &dpapiStore{dir: dir}, nil
}

func (s *dpapiStore) Name() string { return BackendDPAPI }

func (s *dpapiStore) Save(m Material) error {
	if err := s.write(dpapiKeyFile, m.KeyPEM); err != nil {
		return err
	}
	if err := s.write(dpapiCertFile, m.CertPEM); err != nil {
		return err
	}
	if len(m.CSRPEM) > 0 {
		if err := s.write(dpapiCSRFile, m.CSRPEM); err != nil {
			return err
		}
	}
	for _, name := range []string{"agent.key", "agent.crt", "agent.csr", "agent.key.enc", "agent.crt.enc", "agent.csr.enc"} {
		_ = os.Remove(filepath.Join(s.dir, name))
	}
	return nil
}

func (s *dpapiStore) LoadKeyPEM() ([]byte, error)  { return s.read(dpapiKeyFile) }
func (s *dpapiStore) LoadCertPEM() ([]byte, error) { return s.read(dpapiCertFile) }
func (s *dpapiStore) LoadCSRPEM() ([]byte, error)  { return s.read(dpapiCSRFile) }

func (s *dpapiStore) Has() bool {
	_, errK := os.Stat(filepath.Join(s.dir, dpapiKeyFile))
	_, errC := os.Stat(filepath.Join(s.dir, dpapiCertFile))
	return errK == nil && errC == nil
}

func (s *dpapiStore) write(name string, plain []byte) error {
	enc, err := dpapiProtect(plain)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, name), enc, 0o600)
}

func (s *dpapiStore) read(name string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return nil, err
	}
	return dpapiUnprotect(raw)
}

// cryptProtectLocalMachine binds the blob to this computer so LocalSystem
// (the EDRAgent service) and Administrators can unprotect it. User-scope
// DPAPI (the previous default) made enrollment succeed in an interactive
// session and then fail when the service started.
const cryptProtectLocalMachine = 0x4 // CRYPTPROTECT_LOCAL_MACHINE

func dpapiProtect(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("dpapi: empty plaintext")
	}
	in := windows.DataBlob{
		Size: uint32(len(plain)),
		Data: &plain[0],
	}
	var out windows.DataBlob
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN | cryptProtectLocalMachine)
	err := windows.CryptProtectData(&in, nil, nil, 0, nil, flags, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	buf := make([]byte, out.Size)
	copy(buf, unsafe.Slice(out.Data, out.Size))
	return buf, nil
}

func dpapiUnprotect(enc []byte) ([]byte, error) {
	if len(enc) == 0 {
		return nil, fmt.Errorf("dpapi: empty ciphertext")
	}
	in := windows.DataBlob{
		Size: uint32(len(enc)),
		Data: &enc[0],
	}
	// Machine-scope blobs unprotect with UI_FORBIDDEN. Retry with the
	// LOCAL_MACHINE flag, then with user-scope flags, so upgrades can still
	// read credentials sealed before this change (interactive re-enroll).
	flagSets := []uint32{
		windows.CRYPTPROTECT_UI_FORBIDDEN,
		windows.CRYPTPROTECT_UI_FORBIDDEN | cryptProtectLocalMachine,
		0,
	}
	var last error
	for _, flags := range flagSets {
		var out windows.DataBlob
		err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, flags, &out)
		if err != nil {
			last = err
			continue
		}
		buf := make([]byte, out.Size)
		copy(buf, unsafe.Slice(out.Data, out.Size))
		_ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
		return buf, nil
	}
	if last == nil {
		last = fmt.Errorf("dpapi: unprotect failed")
	}
	return nil, last
}
