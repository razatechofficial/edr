//go:build darwin && cgo

package keystore

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef cfstr(const char *s) {
	return CFStringCreateWithCString(kCFAllocatorDefault, s, kCFStringEncodingUTF8);
}

// kc_upsert stores bytes as a generic password (ThisDeviceOnly).
static OSStatus kc_upsert(const char *service, const char *account, const void *data, size_t len) {
	CFStringRef svc = cfstr(service);
	CFStringRef acct = cfstr(account);
	if (svc == NULL || acct == NULL) {
		if (svc) CFRelease(svc);
		if (acct) CFRelease(acct);
		return errSecParam;
	}

	// Delete any existing item first.
	const void *delKeys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
	const void *delVals[] = { kSecClassGenericPassword, svc, acct };
	CFDictionaryRef delQ = CFDictionaryCreate(kCFAllocatorDefault, delKeys, delVals, 3,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (delQ) {
		SecItemDelete(delQ);
		CFRelease(delQ);
	}

	CFDataRef cfData = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)len);
	if (cfData == NULL) {
		CFRelease(svc);
		CFRelease(acct);
		return errSecAllocate;
	}

	const void *addKeys[] = {
		kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData,
		kSecAttrAccessible, kSecAttrSynchronizable
	};
	const void *addVals[] = {
		kSecClassGenericPassword, svc, acct, cfData,
		kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kCFBooleanFalse
	};
	CFDictionaryRef addQ = CFDictionaryCreate(kCFAllocatorDefault, addKeys, addVals, 6,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus st = errSecParam;
	if (addQ) {
		st = SecItemAdd(addQ, NULL);
		CFRelease(addQ);
	}
	CFRelease(cfData);
	CFRelease(svc);
	CFRelease(acct);
	return st;
}

static OSStatus kc_load(const char *service, const char *account, void **out, size_t *outLen) {
	CFStringRef svc = cfstr(service);
	CFStringRef acct = cfstr(account);
	if (svc == NULL || acct == NULL) {
		if (svc) CFRelease(svc);
		if (acct) CFRelease(acct);
		return errSecParam;
	}
	const void *keys[] = {
		kSecClass, kSecAttrService, kSecAttrAccount,
		kSecReturnData, kSecMatchLimit
	};
	const void *vals[] = {
		kSecClassGenericPassword, svc, acct,
		kCFBooleanTrue, kSecMatchLimitOne
	};
	CFDictionaryRef q = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 5,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFTypeRef result = NULL;
	OSStatus st = errSecParam;
	if (q) {
		st = SecItemCopyMatching(q, &result);
		CFRelease(q);
	}
	CFRelease(svc);
	CFRelease(acct);
	if (st != errSecSuccess || result == NULL) {
		return st;
	}
	CFDataRef data = (CFDataRef)result;
	CFIndex n = CFDataGetLength(data);
	void *buf = malloc((size_t)n);
	if (buf == NULL) {
		CFRelease(result);
		return errSecAllocate;
	}
	memcpy(buf, CFDataGetBytePtr(data), (size_t)n);
	CFRelease(result);
	*out = buf;
	*outLen = (size_t)n;
	return errSecSuccess;
}

static OSStatus kc_has(const char *service, const char *account) {
	CFStringRef svc = cfstr(service);
	CFStringRef acct = cfstr(account);
	if (svc == NULL || acct == NULL) {
		if (svc) CFRelease(svc);
		if (acct) CFRelease(acct);
		return errSecParam;
	}
	const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecMatchLimit };
	const void *vals[] = { kSecClassGenericPassword, svc, acct, kSecMatchLimitOne };
	CFDictionaryRef q = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 4,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus st = errSecParam;
	if (q) {
		st = SecItemCopyMatching(q, NULL);
		CFRelease(q);
	}
	CFRelease(svc);
	CFRelease(acct);
	return st;
}
*/
import "C"

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

const kcService = "com.razatech.edr.xdr-identity"

type keychainStore struct {
	dir string // scopes Keychain accounts + CA/enrollment.json sidecar
}

func newKeychainStore(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &keychainStore{dir: dir}, nil
}

func (s *keychainStore) Name() string { return BackendKeychain }

// account names are scoped by cert_dir so multiple agents/tests don't collide.
func (s *keychainStore) acct(kind string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(s.dir)))
	return kind + ":" + hex.EncodeToString(sum[:8])
}

func (s *keychainStore) Save(m Material) error {
	if err := kcUpsert(s.acct("agent-private-key"), m.KeyPEM); err != nil {
		return fmt.Errorf("keychain save key: %w", err)
	}
	if err := kcUpsert(s.acct("agent-certificate"), m.CertPEM); err != nil {
		return fmt.Errorf("keychain save cert: %w", err)
	}
	if len(m.CSRPEM) > 0 {
		if err := kcUpsert(s.acct("agent-csr"), m.CSRPEM); err != nil {
			return fmt.Errorf("keychain save csr: %w", err)
		}
	}
	// Remove any leftover plaintext / sealed file copies of secrets.
	for _, name := range []string{"agent.key", "agent.crt", "agent.csr", "agent.key.enc", "agent.crt.enc", "agent.csr.enc"} {
		_ = os.Remove(filepath.Join(s.dir, name))
	}
	return nil
}

func (s *keychainStore) LoadKeyPEM() ([]byte, error) {
	return kcLoad(s.acct("agent-private-key"))
}
func (s *keychainStore) LoadCertPEM() ([]byte, error) {
	return kcLoad(s.acct("agent-certificate"))
}
func (s *keychainStore) LoadCSRPEM() ([]byte, error) {
	return kcLoad(s.acct("agent-csr"))
}

func (s *keychainStore) Has() bool {
	return kcHas(s.acct("agent-private-key")) && kcHas(s.acct("agent-certificate"))
}

func kcHas(account string) bool {
	svc := C.CString(kcService)
	acct := C.CString(account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	return C.kc_has(svc, acct) == C.errSecSuccess
}

func kcUpsert(account string, data []byte) error {
	svc := C.CString(kcService)
	acct := C.CString(account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	var ptr unsafe.Pointer
	if len(data) > 0 {
		ptr = unsafe.Pointer(&data[0])
	}
	st := C.kc_upsert(svc, acct, ptr, C.size_t(len(data)))
	if st != C.errSecSuccess {
		return fmt.Errorf("SecItemAdd status=%d", int(st))
	}
	return nil
}

func kcLoad(account string) ([]byte, error) {
	svc := C.CString(kcService)
	acct := C.CString(account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	var out unsafe.Pointer
	var n C.size_t
	st := C.kc_load(svc, acct, &out, &n)
	if st != C.errSecSuccess {
		return nil, fmt.Errorf("SecItemCopyMatching status=%d", int(st))
	}
	defer C.free(out)
	return C.GoBytes(out, C.int(n)), nil
}
