package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	encKeyFile  = "agent.key.enc"
	encCertFile = "agent.crt.enc"
	encCSRFile  = "agent.csr.enc"
	encMagic    = "EDRKEY2" // v2: HKDF + machine-id binding
)

type fileStore struct {
	dir     string
	dataDir string
}

func newFileStore(dir, dataDir string) *fileStore {
	return &fileStore{dir: dir, dataDir: dataDir}
}

func (s *fileStore) Name() string { return BackendFile }

func (s *fileStore) ensureDir() error {
	return os.MkdirAll(s.dir, 0o700)
}

func (s *fileStore) Save(m Material) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	if err := s.writeSealed(encKeyFile, m.KeyPEM); err != nil {
		return fmt.Errorf("seal key: %w", err)
	}
	if err := s.writeSealed(encCertFile, m.CertPEM); err != nil {
		return fmt.Errorf("seal cert: %w", err)
	}
	if len(m.CSRPEM) > 0 {
		if err := s.writeSealed(encCSRFile, m.CSRPEM); err != nil {
			return fmt.Errorf("seal csr: %w", err)
		}
	}
	// Remove legacy plaintext / v1 names if present.
	for _, name := range []string{"agent.key", "agent.crt", "agent.csr"} {
		_ = os.Remove(filepath.Join(s.dir, name))
	}
	return nil
}

func (s *fileStore) LoadKeyPEM() ([]byte, error)  { return s.readSealed(encKeyFile) }
func (s *fileStore) LoadCertPEM() ([]byte, error) { return s.readSealed(encCertFile) }
func (s *fileStore) LoadCSRPEM() ([]byte, error)  { return s.readSealed(encCSRFile) }

func (s *fileStore) Has() bool {
	_, errK := os.Stat(filepath.Join(s.dir, encKeyFile))
	_, errC := os.Stat(filepath.Join(s.dir, encCertFile))
	return errK == nil && errC == nil
}

func (s *fileStore) writeSealed(name string, plain []byte) error {
	sealed, err := seal(plain, s.kek())
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, name), sealed, 0o600)
}

func (s *fileStore) readSealed(name string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return nil, err
	}
	if plain, err := open(raw, s.kek()); err == nil {
		return plain, nil
	}
	// Migrate v1 blobs (EDRKEY1 + SHA256 host bind) if present.
	if plain, err := openV1(raw, s.dir, s.dataDir); err == nil {
		return plain, nil
	}
	return open(raw, s.kek())
}

func (s *fileStore) kek() []byte {
	host, _ := os.Hostname()
	mid := readMachineID()
	ikm := []byte(strings.Join([]string{
		"xdr-agent-identity-v2",
		host,
		runtime.GOOS,
		runtime.GOARCH,
		strings.TrimSpace(s.dir),
		strings.TrimSpace(s.dataDir),
		mid,
	}, "|"))
	r := hkdf.New(sha256.New, ikm, []byte("edr-xdr-keystore"), []byte("aes-256-gcm-kek"))
	out := make([]byte, 32)
	_, _ = r.Read(out)
	return out
}

func seal(plain, kek []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, plain, nil)
	out := make([]byte, 0, len(encMagic)+len(ct))
	out = append(out, []byte(encMagic)...)
	out = append(out, ct...)
	return out, nil
}

func open(sealed, kek []byte) ([]byte, error) {
	if len(sealed) < len(encMagic)+12 {
		return nil, fmt.Errorf("sealed blob too short")
	}
	if string(sealed[:len(encMagic)]) != encMagic {
		return nil, fmt.Errorf("unsupported sealed format (expected %s)", encMagic)
	}
	ct := sealed[len(encMagic):]
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ct) < ns {
		return nil, fmt.Errorf("sealed blob truncated")
	}
	return gcm.Open(nil, ct[:ns], ct[ns:], nil)
}

var (
	machineIDOnce sync.Once
	machineIDVal  string
)

func readMachineID() string {
	machineIDOnce.Do(func() {
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			if s := strings.TrimSpace(string(b)); s != "" {
				machineIDVal = s
				return
			}
		}
		// macOS: IOPlatformUUID is stable per hardware (when available).
		if runtime.GOOS == "darwin" {
			if id := darwinPlatformUUID(); id != "" {
				machineIDVal = id
				return
			}
		}
		machineIDVal = "no-machine-id"
	})
	return machineIDVal
}

const encMagicV1 = "EDRKEY1"

func openV1(sealed []byte, dir, dataDir string) ([]byte, error) {
	if len(sealed) < len(encMagicV1)+12 || string(sealed[:len(encMagicV1)]) != encMagicV1 {
		return nil, fmt.Errorf("not v1")
	}
	host, _ := os.Hostname()
	bind := dir
	if strings.TrimSpace(dataDir) != "" {
		// Historical builds sometimes bound to data_dir.
		bind = dataDir
	}
	material := strings.Join([]string{
		"xdr-agent-identity-key",
		host,
		runtime.GOOS,
		runtime.GOARCH,
		strings.TrimSpace(bind),
	}, "|")
	sum := sha256.Sum256([]byte(material))
	// Also try cert-dir binding used after bindDir fix.
	alts := [][]byte{sum[:]}
	material2 := strings.Join([]string{
		"xdr-agent-identity-key",
		host,
		runtime.GOOS,
		runtime.GOARCH,
		strings.TrimSpace(dir),
	}, "|")
	sum2 := sha256.Sum256([]byte(material2))
	alts = append(alts, sum2[:])

	ct := sealed[len(encMagicV1):]
	var last error
	for _, kek := range alts {
		block, err := aes.NewCipher(kek)
		if err != nil {
			last = err
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			last = err
			continue
		}
		ns := gcm.NonceSize()
		if len(ct) < ns {
			last = fmt.Errorf("truncated")
			continue
		}
		plain, err := gcm.Open(nil, ct[:ns], ct[ns:], nil)
		if err == nil {
			return plain, nil
		}
		last = err
	}
	return nil, last
}
